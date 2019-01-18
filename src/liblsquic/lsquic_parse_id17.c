/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_id17.c -- Parsing functions specific to Internet Draft 17
 *                          version of IETF QUIC
 */

#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#ifndef WIN32
#include <sys/types.h>
#else
#include <vc_compat.h>
#endif

#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_parse.h"
#include "lsquic_parse_common.h"
#include "lsquic_sfcw.h"
#include "lsquic_hq.h"
#include "lsquic_varint.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_mm.h"
#include "lsquic_malo.h"
#include "lsquic_version.h"
#include "lsquic.h"
#include "lsquic_byteswap.h"
#include "lsquic_varint.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_trans_params.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PARSE
#include "lsquic_logger.h"

#define CHECK_SPACE(need, pstart, pend)  \
    do { if ((intptr_t) (need) > ((pend) - (pstart))) { return -1; } } while (0)


static void
id17_parse_packet_in_finish (lsquic_packet_in_t *packet_in,
                                            struct packin_parse_state *state)
{
    /* Packet number is encrypted... */
}


/* Note: token size is not accounted for */
static size_t
id17_packout_header_size_long_by_flags (const struct lsquic_conn *lconn,
                enum header_type header_type, enum packet_out_flags flags)
{
    size_t sz;
    enum packno_bits packno_bits;

    packno_bits = (flags >> POBIT_SHIFT) & 0x3;

    sz = 1 /* Type */
       + 4 /* Version */
       + 1 /* DCIL/SCIL */
       + lconn->cn_dcid.len
       + CN_SCID(lconn)->len
       + (header_type == HETY_INITIAL)  /* Token length */
       + 2 /* Always use two bytes to encode payload length */
       + iquic_packno_bits2len(packno_bits)
       ;

    return sz;
}


static size_t
id17_packout_header_size_long_by_packet (const struct lsquic_conn *lconn,
                                const struct lsquic_packet_out *packet_out)
{
    size_t sz;
    unsigned token_len; /* Need intermediate value to quiet compiler warning */
    enum packno_bits packno_bits;

    packno_bits = lsquic_packet_out_packno_bits(packet_out);

    sz = 1 /* Type */
       + 4 /* Version */
       + 1 /* DCIL/SCIL */
       + lconn->cn_dcid.len
       + CN_SCID(lconn)->len
       + (packet_out->po_header_type == HETY_INITIAL ?
            (token_len = packet_out->po_token_len,
                (1 << vint_val2bits(token_len)) + token_len) : 0)
       + 2 /* Always use two bytes to encode payload length */
       + iquic_packno_bits2len(packno_bits)
       ;

    return sz;
}


static size_t
id17_packout_header_size_short (const struct lsquic_conn *lconn,
                                            enum packet_out_flags flags)
{
    enum packno_bits bits;
    size_t sz;

    bits = (flags >> POBIT_SHIFT) & 0x3;
    sz = 1 /* Type */
       + (flags & PO_CONN_ID ? lconn->cn_dcid.len : 0)
       + iquic_packno_bits2len(bits)
       ;

    return sz;
}


static size_t
id17_packout_max_header_size (const struct lsquic_conn *lconn,
                                enum packet_out_flags flags)
{
    if (lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
        return id17_packout_header_size_short(lconn, flags);
    else
        return id17_packout_header_size_long_by_flags(lconn, HETY_INITIAL, flags);
}


/* [draft-ietf-quic-transport-17] Section-17.2 */
static const unsigned char header_type_to_bin[] = {
    [HETY_INITIAL]      = 0x0,
    [HETY_0RTT]         = 0x1,
    [HETY_HANDSHAKE]    = 0x2,
    [HETY_RETRY]        = 0x3,
};


static unsigned
write_packno (unsigned char *p, lsquic_packno_t packno,
                                                enum packno_bits bits)
{
    unsigned char *const begin = p;

    switch (bits)
    {
    case IQUIC_PACKNO_LEN_4:
        *p++ = packno >> 24;
    case IQUIC_PACKNO_LEN_3:
        *p++ = packno >> 16;
    case IQUIC_PACKNO_LEN_2:
        *p++ = packno >> 8;
    default:
        *p++ = packno;
    }

    return p - begin;
}


static int
gen_long_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    unsigned payload_len, bits;
    enum packno_bits packno_bits;
    lsquic_ver_tag_t ver_tag;
    uint8_t dlen, slen;
    unsigned char *p;
    unsigned token_len;
    size_t need;

    need = id17_packout_header_size_long_by_packet(lconn, packet_out);
    if (need > bufsz)
    {
        errno = EINVAL;
        return -1;
    }

    packno_bits = lsquic_packet_out_packno_bits(packet_out);
    p = buf;
    *p++ = 0xC0
         | ( header_type_to_bin[ packet_out->po_header_type ] << 4)
         | packno_bits
         ;
    ver_tag = lsquic_ver2tag(lconn->cn_version);
    memcpy(p, &ver_tag, sizeof(ver_tag));
    p += sizeof(ver_tag);

    dlen = lconn->cn_dcid.len;
    if (dlen)
        dlen -= 3;
    slen = CN_SCID(lconn)->len;
    if (slen)
        slen -= 3;
    *p++ = (dlen << 4) | slen;

    memcpy(p, lconn->cn_dcid.idbuf, lconn->cn_dcid.len);
    p += lconn->cn_dcid.len;
    memcpy(p, CN_SCID(lconn)->idbuf, CN_SCID(lconn)->len);
    p +=  CN_SCID(lconn)->len;

    if (HETY_INITIAL == packet_out->po_header_type)
    {
        token_len = packet_out->po_token_len;
        bits = vint_val2bits(token_len);
        vint_write(p, token_len, bits, 1 << bits);
        p += 1 << bits;
        memcpy(p, packet_out->po_token, token_len);
        p += token_len;
    }

    payload_len = packet_out->po_data_sz
                + lconn->cn_esf_c->esf_tag_len
                + iquic_packno_bits2len(packno_bits);
    bits = 1;   /* Always use two bytes to encode payload length */
    vint_write(p, payload_len, bits, 1 << bits);
    p += 1 << bits;

    p += write_packno(p, packet_out->po_packno,
                                    lsquic_packet_out_packno_bits(packet_out));

    return p - buf;
}


static int
gen_short_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    unsigned packno_len, cid_len, need;
    enum packno_bits packno_bits;

    packno_bits = lsquic_packet_out_packno_bits(packet_out);
    packno_len = iquic_packno_bits2len(packno_bits);
    cid_len = packet_out->po_flags & PO_CONN_ID ? lconn->cn_dcid.len : 0;

    need = 1 + cid_len + packno_len;
    if (need > bufsz)
        return -1;

    buf[0] = 0x40
           | (lsquic_packet_out_spin_bit(packet_out) << 5)
           | (lsquic_packet_out_key_phase(packet_out) << 2)
           | packno_bits
           ;

    if (cid_len)
        memcpy(buf + 1, lconn->cn_dcid.idbuf, cid_len);

    (void) write_packno(buf + 1 + cid_len, packet_out->po_packno, packno_bits);

    return need;
}


static int
id17_gen_reg_pkt_header (const struct lsquic_conn *lconn,
            const struct lsquic_packet_out *packet_out, unsigned char *buf,
                                                                size_t bufsz)
{
    if (packet_out->po_header_type == HETY_NOT_SET)
        return gen_short_pkt_header(lconn, packet_out, buf, bufsz);
    else
        return gen_long_pkt_header(lconn, packet_out, buf, bufsz);
}


static void
id17_packno_info (const struct lsquic_conn *lconn,
        const struct lsquic_packet_out *packet_out, unsigned *packno_off,
        unsigned *packno_len)
{
    unsigned token_len; /* Need intermediate value to quiet compiler warning */

    if (packet_out->po_header_type == HETY_NOT_SET)
        *packno_off = 1 +
            (packet_out->po_flags & PO_CONN_ID ? lconn->cn_dcid.len : 0);
    else
        *packno_off = 1
                    + 4
                    + 1
                    + lconn->cn_dcid.len
                    + CN_SCID(lconn)->len
                    + (packet_out->po_header_type == HETY_INITIAL ?
                        (token_len = packet_out->po_token_len,
                            (1 << vint_val2bits(token_len)) + token_len) : 0)
                    + 2;
    *packno_len = iquic_packno_bits2len(
        lsquic_packet_out_packno_bits(packet_out));
}


static size_t
id17_packout_size (const struct lsquic_conn *lconn,
                                const struct lsquic_packet_out *packet_out)
{
    size_t sz;

    if ((lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
                                && packet_out->po_header_type == HETY_NOT_SET)
        sz = id17_packout_header_size_short(lconn, packet_out->po_flags);
    else
        sz = id17_packout_header_size_long_by_packet(lconn, packet_out);

    sz += packet_out->po_data_sz;
    sz += lconn->cn_esf_c->esf_tag_len;

    return sz;
}


static int
id17_gen_stream_frame (unsigned char *buf, size_t buf_len,
        lsquic_stream_id_t stream_id, uint64_t offset, int fin, size_t size,
        gsf_read_f gsf_read, void *stream)
{
    /* 0b00001XXX
     *  0x4     OFF
     *  0x2     LEN
     *  0x1     FIN
     */
    unsigned sbits, obits, dbits;
    unsigned slen, olen, dlen;
    unsigned char *p = buf + 1;

    assert(!!fin ^ !!size);

    /* We do not check that stream_id, offset, and size are smaller
     * than 2^62: this is not necessary, as this code will never generate
     * this many stream IDs, nor will it even transfer this much data.
     * The size is limited by our own code.
     */

    sbits = vint_val2bits(stream_id);
    slen = 1 << sbits;
    if (offset)
    {
        obits = vint_val2bits(offset);
        olen = 1 << obits;
    }
    else
        olen = 0;

    if (!fin)
    {
        unsigned n_avail;
        size_t nr;

        n_avail = buf_len - (p + slen + olen - buf);

        /* If we cannot fill remaining buffer, we need to include data
         * length.
         */
        if (size < n_avail)
        {
            dbits = vint_val2bits(size);
            dlen = 1 << dbits;
            n_avail -= dlen;
            if (size > n_avail)
                size = n_avail;
        }
        else
        {
            dlen = 0;
            size = n_avail;
        }

        CHECK_STREAM_SPACE(1 + olen + slen + dlen +
            + 1 /* We need to write at least 1 byte */, buf, buf + buf_len);

        vint_write(p, stream_id, sbits, slen);
        p += slen;

        if (olen)
            vint_write(p, offset, obits, olen);
        p += olen;

        /* Read as much as we can */
        nr = gsf_read(stream, p + dlen, size, &fin);
        assert(nr != 0);
        assert(nr <= size);

        if (dlen)
            vint_write(p, nr, dbits, dlen);

        p += dlen + nr;
    }
    else
    {
        dlen = 1 + slen + olen < buf_len;
        CHECK_STREAM_SPACE(1 + slen + olen + dlen, buf, buf + buf_len);
        vint_write(p, stream_id, sbits, slen);
        p += slen;
        if (olen)
            vint_write(p, offset, obits, olen);
        p += olen;
        if (dlen)
            *p++ = 0;
    }

    buf[0] = 0x08
           | (!!olen << 2)
           | (!!dlen << 1)
           | (!!fin  << 0)
           ;
    return p - buf;
}


static int
id17_gen_crypto_frame (unsigned char *buf, size_t buf_len,
        uint64_t offset, size_t size, gcf_read_f gcf_read, void *stream)
{
    unsigned char *const end = buf + buf_len;
    unsigned char *p;
    unsigned obits, dbits;
    unsigned olen, dlen;
    size_t nr, n_avail;

    obits = vint_val2bits(offset);
    olen = 1 << obits;
    dbits = vint_val2bits(size);
    dlen = 1 << dbits;

    CHECK_SPACE(1 + olen + dlen
        + (dlen > 0) /* We need to write at least 1 byte */, buf, end);

    n_avail = end - buf - 1 - olen - dlen;
    if (n_avail < size)
        size = n_avail;

    p = buf;
    *p++ = 0x06;

    vint_write(p, offset, obits, olen);
    p += olen;

    nr = gcf_read(stream, p + dlen, size);
    assert(nr != 0);    /* This indicates error in the caller */
    assert(nr <= size); /* This also indicates an error in the caller */

    vint_write(p, nr, dbits, dlen);
    p += dlen + nr;

    return p - buf;
}


/* return parsed (used) buffer length */
static int
id17_parse_stream_frame (const unsigned char *buf, size_t rem_packet_sz,
                                        struct stream_frame *stream_frame)
{
    /* 0b00001XXX
     *  0x4     OFF
     *  0x2     LEN
     *  0x1     FIN
     */
    const unsigned char *const pend = buf + rem_packet_sz;
    const unsigned char *p = buf;
    lsquic_stream_id_t stream_id;
    uint64_t offset, data_sz;
    int r;

    CHECK_SPACE(1, p, pend);
    const char type = *p++;

    r = vint_read(p, pend, &stream_id);
    if (r < 0)
        return -1;
    p += r;

    if (type & 0x4)
    {
        r = vint_read(p, pend, &offset);
        if (r < 0)
            return -1;
        p += r;
    }
    else
        offset = 0;

    if (type & 0x2)
    {
        r = vint_read(p, pend, &data_sz);
        if (r < 0)
            return -1;
        p += r;
        CHECK_SPACE(data_sz, p, pend);
    }
    else
        data_sz = pend - p;

    stream_frame->stream_id             = stream_id;
    stream_frame->data_frame.df_fin     = type & 0x1;
    stream_frame->data_frame.df_offset  = offset;
    stream_frame->data_frame.df_size    = data_sz;
    stream_frame->data_frame.df_data    = p;
    stream_frame->data_frame.df_read_off= 0;
    stream_frame->packet_in             = NULL;

    assert(p <= pend);

    return p + data_sz - (unsigned char *) buf;
}


static int
id17_parse_crypto_frame (const unsigned char *buf, size_t rem_packet_sz,
                                        struct stream_frame *stream_frame)
{
    const unsigned char *const pend = buf + rem_packet_sz;
    const unsigned char *p = buf;
    uint64_t offset, data_sz;
    int r;

    CHECK_SPACE(1, p, pend);

    assert(0x06 == *p);
    ++p;

    r = vint_read(p, pend, &offset);
    if (r < 0)
        return -1;
    p += r;

    r = vint_read(p, pend, &data_sz);
    if (r < 0)
        return -1;
    p += r;
    CHECK_SPACE(data_sz, p, pend);

    stream_frame->stream_id             = ~0ULL;    /* Unset */
    stream_frame->data_frame.df_fin     = 0;
    stream_frame->data_frame.df_offset  = offset;
    stream_frame->data_frame.df_size    = data_sz;
    stream_frame->data_frame.df_data    = p;
    stream_frame->data_frame.df_read_off= 0;
    stream_frame->packet_in             = NULL;

    assert(p <= pend);

    return p + data_sz - (unsigned char *) buf;
}


#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
#endif


static int
id17_parse_ack_frame (const unsigned char *const buf, size_t buf_len,
                                            struct ack_info *ack, uint8_t exp)
{
    const unsigned char *p = buf;
    const unsigned char *const end = buf + buf_len;
    uint64_t block_count, gap, block;
    enum ecn ecn;
    unsigned i;
    int r;

    ++p;
    r = vint_read(p, end, &ack->ranges[0].high);
    if (UNLIKELY(r < 0))
        return -1;
    p += r;
    r = vint_read(p, end, &ack->lack_delta);
    if (UNLIKELY(r < 0))
        return -1;
    p += r;
    ack->lack_delta <<= exp;
    r = vint_read(p, end, &block_count);
    if (UNLIKELY(r < 0))
        return -1;
    p += r;
    r = vint_read(p, end, &block);
    if (UNLIKELY(r < 0))
        return -1;
    ack->ranges[0].low = ack->ranges[0].high - block;
    if (UNLIKELY(ack->ranges[0].high < ack->ranges[0].low))
        return -1;
    p += r;

    for (i = 1; i <= block_count; ++i)
    {
        r = vint_read(p, end, &gap);
        if (UNLIKELY(r < 0))
            return -1;
        p += r;
        r = vint_read(p, end, &block);
        if (UNLIKELY(r < 0))
            return -1;
        p += r;
        if (i < sizeof(ack->ranges) / sizeof(ack->ranges[0]))
        {
            ack->ranges[i].high = ack->ranges[i - 1].low - gap - 2;
            ack->ranges[i].low  = ack->ranges[i].high - block;
            if (UNLIKELY(ack->ranges[i].high >= ack->ranges[i - 1].low
                         || ack->ranges[i].high < ack->ranges[i].low))
                return -1;
        }
    }

    if (i < sizeof(ack->ranges) / sizeof(ack->ranges[0]))
    {
        ack->flags = 0;
        ack->n_ranges = block_count + 1;
    }
    else
    {
        ack->flags = AI_TRUNCATED;
        ack->n_ranges = sizeof(ack->ranges) / sizeof(ack->ranges[0]);
    }


    if (0x03 == buf[0])
    {
        for (ecn = 1; ecn <= 3; ++ecn)
        {
            r = vint_read(p, end, &ack->ecn_counts[ecn]);
            if (UNLIKELY(r < 0))
                return -1;
            p += r;
        }
        ack->flags |= AI_ECN;
    }

#if LSQUIC_PARSE_ACK_TIMESTAMPS
#error Pasing ACK timestamps not supported
#else
    ack->n_timestamps = 0;
#endif

    return p - buf;
}


static int
id17_gen_rst_frame (unsigned char *buf, size_t buf_len,
        lsquic_stream_id_t stream_id64, uint64_t offset, uint32_t error_code)
{
    assert(0);  /* Not implemented for ID-11 yet */
    uint32_t stream_id = stream_id64;
    unsigned char *p = buf;
    if (buf_len < GQUIC_RST_STREAM_SZ)
        return -1;

    *p = 0x01;
    ++p;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    stream_id = bswap_32(stream_id);
#endif
    memcpy(p, &stream_id, 4);
    p += 4;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    offset = bswap_64(offset);
#endif
    memcpy(p, &offset, 8);
    p += 8;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    error_code = bswap_32(error_code);
#endif
    memcpy(p, &error_code, 4);
    p += 4;
    return p - buf;
}


static int
id17_parse_rst_frame (const unsigned char *buf, size_t buf_len,
    lsquic_stream_id_t *stream_id_p, uint64_t *offset_p, uint32_t *error_code_p)
{
    const unsigned char *p = buf + 1;
    const unsigned char *const end = buf + buf_len;
    uint64_t stream_id, offset;
    uint16_t error_code;
    int r;

    r = vint_read(p, end, &stream_id);
    if (r < 0)
        return r;
    p += r;

    if (end - p < 2)
        return -1;

    READ_UINT(error_code, 16, p, 2);
    p += 2;

    r = vint_read(p, end, &offset);
    if (r < 0)
        return r;
    p += r;

    *stream_id_p = stream_id;
    *offset_p = offset;
    *error_code_p = error_code;

    return p - buf;
}


static int
id17_parse_stop_sending_frame (const unsigned char *buf, size_t buf_len,
                        lsquic_stream_id_t *stream_id, uint16_t *error_code)
{
    const unsigned char *p = buf + 1;
    const unsigned char *const end = buf + buf_len;
    int r;

    if (end - p < 3)
        return -1;

    r = vint_read(p, end, stream_id);
    if (r < 0)
        return r;
    p += r;

    if (end - p < 2)
        return -1;

    READ_UINT(*error_code, 16, p, 2);
    p += 2;

    return p - buf;
}


static int
id17_parse_new_token_frame (const unsigned char *buf, size_t buf_len,
                            const unsigned char **token, size_t *token_size_p)
{
    uint64_t token_size;
    const unsigned char *p = buf + 1;
    const unsigned char *const end = buf + buf_len;
    int r;

    if (end - p < 2)
        return -1;

    r = vint_read(p, end, &token_size);
    if (r < 0)
        return r;
    p += r;

    if (p + token_size > end)
        return -1;
    *token = p;
    p += token_size;
    *token_size_p = token_size;

    return p - buf;
}


static int
id17_gen_ping_frame (unsigned char *buf, int buf_len)
{
    if (buf_len > 0)
    {
        buf[0] = 0x01;
        return 1;
    }
    else
        return -1;
}


static int
id17_gen_connect_close_frame (unsigned char *buf, size_t buf_len,
    int app_error, unsigned error_code, const char *reason, int reason_len)
{
    size_t needed;
    unsigned bits;
    uint16_t ecode;
    unsigned char *p;

    assert(!!reason == !!reason_len);

    bits = vint_val2bits(reason_len);
    needed = 1 /* Type */ + sizeof(ecode) /* Error code */
           + (app_error ? 0 : 1) /* Frame type */
        /* TODO: frame type instead of just zero */
           + (1 << bits) + reason_len;

    if (buf_len < needed)
        return -1;

    p = buf;
    *p = 0x1C + !!app_error;
    ++p;
    ecode = error_code;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    ecode = bswap_16(ecode);
#endif
    memcpy(p, &ecode, sizeof(ecode));
    p += sizeof(ecode);
    if (!app_error)
        *p++ = 0;   /* Frame type */ /* TODO */
    vint_write(p, reason_len, bits, 1 << bits);
    p += 1 << bits;
    if (reason_len)
    {
        memcpy(p, reason, reason_len);
        p += reason_len;
    }

    assert((unsigned) (p - buf) == needed);
    return p - buf;
}


static int
id17_parse_connect_close_frame (const unsigned char *buf, size_t buf_len,
        int *app_error_p, unsigned *error_code, uint16_t *reason_len,
        uint8_t *reason_offset)
{
    const unsigned char *const pend = buf + buf_len;
    const unsigned char *p;
    uint64_t len;
    uint16_t code;
    ptrdiff_t off;
    int app_error, r;

    if (buf_len < 1 + 2 + 1)
        return -1;

    p = buf + 1;
    memcpy(&code, p, 2);
    p += 2;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    code = bswap_16(code);
#endif

    app_error = buf[0] == 0x1D;
    if (!app_error)
    {
        r = vint_read(p, pend, &len);
        if (r < 0)
            return -1;
        p += r;
    }

    r = vint_read(p, pend, &len);
    if (r < 0)
        return -1;
    p += r;

    off = p - buf;
    if (buf_len < off + len)
        return -2;

    *app_error_p = app_error;
    *error_code = code;
    *reason_len = len;
    *reason_offset = off;
    return off + len;
}


/* Returns number of bytes written or -1 on failure */
/* This function makes an assumption that there is at least one range */
static int
id17_gen_ack_frame (unsigned char *outbuf, size_t outbuf_sz,
        gaf_rechist_first_f rechist_first, gaf_rechist_next_f rechist_next,
        gaf_rechist_largest_recv_f rechist_largest_recv,
        void *rechist, lsquic_time_t now, int *has_missing,
        lsquic_packno_t *largest_received, const uint64_t *ecn_counts)
{
    unsigned char *block_count_p, *p = outbuf;
    unsigned char *const end = p + outbuf_sz;
    lsquic_time_t time_diff;
    lsquic_packno_t packno_diff, gap, prev_low, maxno, rsize;
    size_t sz;
    const struct lsquic_packno_range *range;
    unsigned a, b, c, addl_ack_blocks;
    unsigned bits[4];
    enum ecn ecn;

#define AVAIL() (end - p)

#define CHECKOUT(sz) do {                                               \
    if ((intptr_t) (sz) > AVAIL()) {                                    \
        errno = ENOBUFS;                                                \
        return -1;                                                      \
    }                                                                   \
} while (0)

    range = rechist_first(rechist);
    if (!range)
    {
        errno = EINVAL;
        return -1;
    }
    // LSQ_DEBUG("range [%"PRIu64" - %"PRIu64"]", range->high, range->low);

    time_diff = now - rechist_largest_recv(rechist);
    time_diff >>= TP_DEF_ACK_DELAY_EXP;

    maxno = range->high;
    packno_diff = maxno - range->low;

    a = vint_val2bits(maxno);
    b = vint_val2bits(time_diff);
    c = vint_val2bits(packno_diff);
    sz = 1          /* Type */
       + (1 << a)   /* Largest Acknowledged */
       + (1 << b)   /* ACK Delay */
       + 1          /* ACK Block Count */
       + (1 << c)   /* ACK Blocks */
       ;

    CHECKOUT(sz);

    *p = 0x02 + !!ecn_counts;
    ++p;

    vint_write(p, maxno, a, 1 << a);
    p += 1 << a;
    vint_write(p, time_diff, b, 1 << b);
    p += 1 << b;
    block_count_p = p;
    p += 1; /* Initial guess that we have fewer than 64 additional ACK Blocks */
    vint_write(p, packno_diff, c, 1 << c);
    p += 1 << c;

    prev_low = range->low;
    addl_ack_blocks = 0;
    while ((range = rechist_next(rechist)))
    {
        // LSQ_DEBUG("range [%"PRIu64" - %"PRIu64"]", range->high, range->low);
        gap = prev_low - range->high - 1;
        rsize = range->high - range->low;
        a = vint_val2bits(gap - 1);
        b = vint_val2bits(rsize);
        if (addl_ack_blocks == VINT_MAX_ONE_BYTE)
        {
            memmove(block_count_p + 2, block_count_p + 1,
                                                p - block_count_p - 1);
            ++p;
        }
        CHECKOUT((1 << a) + (1 << b));
        vint_write(p, gap - 1, a, 1 << a);
        p += 1 << a;
        vint_write(p, rsize, b, 1 << b);
        p += 1 << b;
        ++addl_ack_blocks;
        prev_low = range->low;
    }

    /* Here we assume that addl_ack_blocks < (1 << 14), which is a safe
     * assumption to make.
     */
    vint_write(block_count_p, addl_ack_blocks,
                        addl_ack_blocks > VINT_MAX_ONE_BYTE,
                        1 + (addl_ack_blocks > VINT_MAX_ONE_BYTE));

    if (ecn_counts)
    {
        for (ecn = 1; ecn <= 3; ++ecn)
            bits[ecn] = vint_val2bits(ecn_counts[ecn]);
        CHECKOUT((1 << bits[1]) + (1 << bits[2]) + (1 << bits[3]));
        for (ecn = 1; ecn <= 3; ++ecn)
        {
            vint_write(p, ecn_counts[ecn], bits[ecn], 1 << bits[ecn]);
            p += 1 << bits[ecn];
        }
    }

    *has_missing = addl_ack_blocks > 0;
    *largest_received = maxno;
    return p - (unsigned char *) outbuf;

#undef CHECKOUT
#undef AVAIL
}


static size_t
id17_calc_stream_frame_header_sz (lsquic_stream_id_t stream_id,
                                            uint64_t offset, unsigned data_sz)
{
    if (offset)
        return 1
            + (1 << vint_val2bits(stream_id))
            + (1 << vint_val2bits(data_sz))
            + (1 << vint_val2bits(offset));
    else
        return 1
            + (1 << vint_val2bits(data_sz))
            + (1 << vint_val2bits(stream_id));
}


static size_t
id17_calc_crypto_frame_header_sz (uint64_t offset)
{
    return 1    /* Frame type */
         + (1 << vint_val2bits(offset))
         + 1    /* Data len */
         ;
}


static enum quic_frame_type
id17_parse_frame_type (unsigned char byte)
{
    return lsquic_iquic_byte2type[byte];
}


static int
id17_parse_path_chal_frame (const unsigned char *buf, size_t len,
                                                            uint64_t *chal)
{
    if (len > 9)
    {
        memcpy(chal, buf + 1, 8);
        return 9;
    }
    else
        return -1;
}


static int
id17_parse_path_resp_frame (const unsigned char *buf, size_t len,
                                                            uint64_t *resp)
{
    return id17_parse_path_chal_frame(buf, len, resp);
}


void
id17_turn_on_fin (unsigned char *stream_frame_header)
{
    *stream_frame_header |= 1;
}


static unsigned
id17_packno_bits2len (enum packno_bits bits)
{
    return iquic_packno_bits2len(bits);
}


static enum packno_bits
id17_calc_packno_bits (lsquic_packno_t packno,
                    lsquic_packno_t least_unacked, uint64_t n_in_flight)
{
    uint64_t delta;
    unsigned bits;

    delta = packno - least_unacked;
    if (n_in_flight > delta)
        delta = n_in_flight;

    delta *= 4;
    bits = (delta >= (1ULL <<  8))
         + (delta >= (1ULL << 16))
         + (delta >= (1ULL << 24))
         ;

    return bits;
}


static int
id17_parse_one_varint (const unsigned char *buf, size_t len, uint64_t *val)
{
    int s;

    s = vint_read(buf + 1, buf + len, val);
    if (s >= 0)
        return 1 + s;
    else
        return s;
}


static int
id17_gen_one_varint (unsigned char *buf, size_t len,
                                        unsigned char type, uint64_t val)
{
    unsigned vbits;
    unsigned char *p;

    vbits = vint_val2bits(val);

    if (1u + (1u << vbits) > len)
        return -1;

    p = buf;
    *p++ = type;
    vint_write(p, val, vbits, 1 << vbits);
    p += 1 << vbits;

    return p - buf;
}


/* Size of a frame that contains one varint */
static unsigned
id17_one_varint_size (uint64_t val)
{
    unsigned vbits;

    vbits = vint_val2bits(val);
    return 1u + (1u << vbits);
}


static int
id17_gen_blocked_frame (unsigned char *buf, size_t buf_len, uint64_t off)
{
    return id17_gen_one_varint(buf, buf_len, 0x14, off);
}


static int
id17_parse_blocked_frame (const unsigned char *buf, size_t sz, uint64_t *off)
{
    return id17_parse_one_varint(buf, sz, off);
}


static unsigned
id17_blocked_frame_size (uint64_t off)
{
    return id17_one_varint_size(off);
}


static int
id17_parse_max_data (const unsigned char *buf, size_t len, uint64_t *val)
{
    return id17_parse_one_varint(buf, len, val);
}


static int
id17_gen_max_data_frame (unsigned char *buf, size_t len, uint64_t val)
{
    return id17_gen_one_varint(buf, len, 0x10, val);
}


static unsigned
id17_max_data_frame_size (uint64_t val)
{
    return id17_one_varint_size(val);
}


static int
id17_parse_retire_cid_frame (const unsigned char *buf, size_t len,
                                                                uint64_t *val)
{
    return id17_parse_one_varint(buf, len, val);
}


static int
id17_gen_retire_cid_frame (unsigned char *buf, size_t len, uint64_t val)
{
    return id17_gen_one_varint(buf, len, 0x19, val);
}


static size_t
id17_retire_cid_frame_size (uint64_t val)
{
    return id17_one_varint_size(val);
}


static int
id17_parse_new_conn_id (const unsigned char *buf, size_t len, uint64_t *seqno,
                        lsquic_cid_t *cid, const unsigned char **reset_token)
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + len;
    unsigned char cid_len;
    int s;

    if (len < 3)
        return -1;

    ++p;    /* Frame type */

    s = vint_read(p, end, seqno);
    if (s < 0)
        return s;
    p += s;

    if (p >= end)
        return -1;

    cid_len = *p++;

    if ((unsigned) (end - p) < cid_len + IQUIC_SRESET_TOKEN_SZ)
        return -1;
    cid->len = cid_len;
    memcpy(cid->idbuf, p, cid_len);
    p += cid_len;
    if (reset_token)
        *reset_token = p;
    p += IQUIC_SRESET_TOKEN_SZ;

    return p - buf;
}


/* Size of a frame that contains two varints */
static unsigned
id17_two_varints_size (uint64_t vals[2])
{
    unsigned vbits[2];

    vbits[0] = vint_val2bits(vals[0]);
    vbits[1] = vint_val2bits(vals[1]);
    return 1u + (1u << vbits[0]) + (1u << vbits[1]);
}


static int
id17_gen_two_varints (unsigned char *buf, size_t len,
                                    unsigned char type, uint64_t vals[2])
{
    unsigned vbits[2];
    unsigned char *p;

    vbits[0] = vint_val2bits(vals[0]);
    vbits[1] = vint_val2bits(vals[1]);

    if (1u + (1u << vbits[0]) + (1u << vbits[1]) > len)
        return -1;

    p = buf;
    *p++ = type;
    vint_write(p, vals[0], vbits[0], 1 << vbits[0]);
    p += 1 << vbits[0];
    vint_write(p, vals[1], vbits[1], 1 << vbits[1]);
    p += 1 << vbits[1];

    return p - buf;
}


static int
id17_parse_two_varints (const unsigned char *buf, size_t len, uint64_t *vals[2])
{
    const unsigned char *p = buf;
    const unsigned char *const end = p + len;
    int s;

    if (len < 2)
        return -1;

    ++p;    /* Type */

    s = vint_read(p, end, vals[0]);
    if (s < 0)
        return s;
    p += s;

    s = vint_read(p, end, vals[1]);
    if (s < 0)
        return s;
    p += s;

    return p - buf;
}


static int
id17_parse_stream_blocked_frame (const unsigned char *buf, size_t len,
                            lsquic_stream_id_t *stream_id, uint64_t *offset)
{
    return id17_parse_two_varints(buf, len,
                                       (uint64_t *[]) { stream_id, offset, });
}


static unsigned
id17_stream_blocked_frame_size (lsquic_stream_id_t stream_id, uint64_t off)
{
    return id17_two_varints_size((uint64_t []) { stream_id, off, });
}


static int
id17_gen_stream_blocked_frame (unsigned char *buf, size_t len,
                                    lsquic_stream_id_t stream_id, uint64_t off)
{
    return id17_gen_two_varints(buf, len, 0x15, (uint64_t[]){ stream_id, off, });
}


static int
id17_gen_max_stream_data_frame (unsigned char *buf, size_t len,
                                    lsquic_stream_id_t stream_id, uint64_t off)
{
    return id17_gen_two_varints(buf, len, 0x11, (uint64_t[]){ stream_id, off, });
}


static unsigned
id17_max_stream_data_frame_size (lsquic_stream_id_t stream_id, uint64_t off)
{
    return id17_two_varints_size((uint64_t []) { stream_id, off, });
}


static int
id17_parse_max_stream_data_frame (const unsigned char *buf, size_t len,
                                lsquic_stream_id_t *stream_id, uint64_t *off)
{
    return id17_parse_two_varints(buf, len, (uint64_t *[]){ stream_id, off, });
}


static int
id17_parse_max_streams_frame (const unsigned char *buf, size_t len,
                                    enum stream_dir *sd, uint64_t *max_streams)
{
    int s;

    s = id17_parse_one_varint(buf, len, max_streams);
    if (s > 0)
        *sd = buf[0] == 0x12 ? SD_BIDI : SD_UNI;
    return s;
}


static size_t
id17_new_connection_id_frame_size (unsigned seqno, unsigned scid_len)
{
    unsigned bits;

    bits = vint_val2bits(seqno);
    return 1 + 1 + (1 << bits) + scid_len + IQUIC_SRESET_TOKEN_SZ;
}


int
id17_gen_new_connection_id_frame (unsigned char *buf, size_t buf_sz,
            unsigned seqno, const struct lsquic_cid *cid,
            const unsigned char *token, size_t token_sz)
{
    unsigned char *p;
    unsigned bits;

    if (buf_sz < id17_new_connection_id_frame_size(seqno, cid->len))
        return -1;

    p = buf;
    *p++ = 0x18;
    bits = vint_val2bits(seqno);
    vint_write(p, seqno, bits, 1 << bits);
    p += 1 << bits;
    *p++ = cid->len;
    memcpy(p, cid->idbuf, cid->len);
    p += cid->len;
    memcpy(p, token, token_sz);
    p += token_sz;

    return p - buf;
}


/* [draft-ietf-quic-transport-17] Section-17.2 */
static const enum header_type bits2ht[4] =
{
    [0] = HETY_INITIAL,
    [1] = HETY_0RTT,
    [2] = HETY_HANDSHAKE,
    [3] = HETY_RETRY,
};


int
lsquic_ID17_parse_packet_in_long_begin (struct lsquic_packet_in *packet_in,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *state)
{
    const unsigned char *p = packet_in->pi_data;
    const unsigned char *const end = p + length;
    lsquic_ver_tag_t tag;
    enum header_type header_type;
    unsigned dcil, scil, odcil;
    int verneg, r;
    unsigned char first_byte;
    uint64_t payload_len, token_len;

    if (length < 6)
        return -1;
    first_byte = *p++;

    memcpy(&tag, p, 4);
    p += 4;
    verneg = 0 == tag;
    if (!verneg)
        header_type = bits2ht[ (first_byte >> 4) & 3 ];
    else
        header_type = HETY_VERNEG;

    packet_in->pi_header_type = header_type;

    dcil = p[0] >> 4;
    if (dcil)
        dcil += 3;
    scil = p[0] & 0xF;
    if (scil)
        scil += 3;
    ++p;

    if (end - p < (ptrdiff_t) (dcil + scil))
        return -1;

    if (dcil)
    {
        memcpy(packet_in->pi_dcid.idbuf, p, dcil);
        packet_in->pi_flags |= PI_CONN_ID;
        p += dcil;
    }
    packet_in->pi_dcid.len = dcil;
    if (scil)
    {
        memcpy(packet_in->pi_scid.idbuf, p, scil);
        p += scil;
    }
    packet_in->pi_scid.len = scil;

    switch (header_type)
    {
    case HETY_INITIAL:
        r = vint_read(p, end, &token_len);
        if (r < 0)
            return -1;
        if (token_len && !is_server)
        {
            /* From [draft-ietf-quic-transport-14]:
             *
             *  Token Length:  A variable-length integer specifying the
             *  length of the Token field, in bytes.  This value is zero
             *  if no token is present.  Initial packets sent by the
             *  server MUST set the Token Length field to zero; clients
             *  that receive an Initial packet with a non-zero Token
             *  Length field MUST either discard the packet or generate
             *  a connection error of type PROTOCOL_VIOLATION.
             */
            return -1;
        }
        p += r;
        if (token_len)
        {
            if (token_len >=
                        1ull << (sizeof(packet_in->pi_token_size) * 8))
                return -1;
            if (p + token_len > end)
                return -1;
            packet_in->pi_token = p - packet_in->pi_data;
            packet_in->pi_token_size = token_len;
            p += token_len;
        }
        /* fall-through */
    case HETY_HANDSHAKE:
    case HETY_0RTT:
        if (p >= end)
            return -1;
        r = vint_read(p, end, &payload_len);
        if (r < 0)
            return -1;
        p += r;
        if (p - packet_in->pi_data + payload_len > length)
            return -1;
        length = p - packet_in->pi_data + payload_len;
        if (end - p < 4)
            return -1;
        state->pps_p      = p - r;
        state->pps_nbytes = r;
        packet_in->pi_quic_ver = 1;
        break;
    case HETY_RETRY:
        odcil = 3 + (first_byte & 0xF);
        if (p + odcil > end)
            return -1;
        packet_in->pi_odcid_len = odcil;
        packet_in->pi_odcid = p - packet_in->pi_data;
        p += odcil;
        packet_in->pi_token = p - packet_in->pi_data;
        packet_in->pi_token_size = end - p;
        p = end;
        length = end - packet_in->pi_data;
        state->pps_p      = NULL;
        state->pps_nbytes = 0;
        packet_in->pi_quic_ver = 1;
        break;
    default:
        assert(header_type == HETY_VERNEG);
        if (p >= end || (3 & (uintptr_t) (end - p)))
            return -1;
        packet_in->pi_quic_ver = p - packet_in->pi_data;
        p = end;
        state->pps_p      = NULL;
        state->pps_nbytes = 0;
        break;
    }

    packet_in->pi_header_sz     = p - packet_in->pi_data;
    packet_in->pi_data_sz       = length;
    packet_in->pi_nonce         = 0;
    packet_in->pi_refcnt        = 0;
    packet_in->pi_frame_types   = 0;
    memset(&packet_in->pi_next, 0, sizeof(packet_in->pi_next));
    packet_in->pi_refcnt        = 0;
    packet_in->pi_received      = 0;

    /* Packet number is set to an invalid value.  The packet number must
     * be decrypted, which happens later.
     */
    packet_in->pi_packno        = 1ULL << 62;

    return 0;
}


int
lsquic_ID17_parse_packet_in_short_begin (struct lsquic_packet_in *packet_in,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *state)
{
    unsigned char byte;
    unsigned header_sz;

    /* By the time this function has been called, we know length is non-zero */
    byte = packet_in->pi_data[0];

    /* [draft-ietf-quic-transport-17] Section 17.3 */
    /* 01SRRKPP */

    header_sz = 1 + cid_len;
    if (length < header_sz)
        return -1;

    memcpy(packet_in->pi_dcid.idbuf, packet_in->pi_data + 1, cid_len);
    packet_in->pi_dcid.len = cid_len;
    packet_in->pi_flags |= PI_CONN_ID;
    packet_in->pi_flags |= ((byte & 0x20) > 0) << PIBIT_KEY_PHASE_SHIFT;

    packet_in->pi_header_sz     = header_sz;
    packet_in->pi_data_sz       = length;
    packet_in->pi_quic_ver      = 0;
    packet_in->pi_nonce         = 0;
    packet_in->pi_refcnt        = 0;
    packet_in->pi_frame_types   = 0;
    memset(&packet_in->pi_next, 0, sizeof(packet_in->pi_next));
    packet_in->pi_refcnt        = 0;
    packet_in->pi_received      = 0;

    /* Packet number is set to an invalid value.  The packet number must
     * be decrypted, which happens later.
     */
    packet_in->pi_packno        = 1ULL << 62;

    return 0;
}


const struct parse_funcs lsquic_parse_funcs_id17 =
{
    .pf_gen_reg_pkt_header            =  id17_gen_reg_pkt_header,
    .pf_parse_packet_in_finish        =  id17_parse_packet_in_finish,
    .pf_gen_stream_frame              =  id17_gen_stream_frame,
    .pf_calc_stream_frame_header_sz   =  id17_calc_stream_frame_header_sz,
    .pf_parse_stream_frame            =  id17_parse_stream_frame,
    .pf_parse_ack_frame               =  id17_parse_ack_frame,
    .pf_gen_ack_frame                 =  id17_gen_ack_frame,
    .pf_gen_blocked_frame             =  id17_gen_blocked_frame,
    .pf_parse_blocked_frame           =  id17_parse_blocked_frame,
    .pf_blocked_frame_size            =  id17_blocked_frame_size,
    .pf_gen_rst_frame                 =  id17_gen_rst_frame,
    .pf_parse_rst_frame               =  id17_parse_rst_frame,
    .pf_gen_connect_close_frame       =  id17_gen_connect_close_frame,
    .pf_parse_connect_close_frame     =  id17_parse_connect_close_frame,
    .pf_gen_ping_frame                =  id17_gen_ping_frame,
    .pf_parse_frame_type              =  id17_parse_frame_type,
    .pf_turn_on_fin                   =  id17_turn_on_fin,
    .pf_packout_size                  =  id17_packout_size,
    .pf_packout_max_header_size       =  id17_packout_max_header_size,
    .pf_parse_path_chal_frame         =  id17_parse_path_chal_frame,
    .pf_parse_path_resp_frame         =  id17_parse_path_resp_frame,
    .pf_calc_packno_bits              =  id17_calc_packno_bits,
    .pf_packno_bits2len               =  id17_packno_bits2len,
    .pf_packno_info                   =  id17_packno_info,
    .pf_gen_crypto_frame              =  id17_gen_crypto_frame,
    .pf_parse_crypto_frame            =  id17_parse_crypto_frame,
    .pf_calc_crypto_frame_header_sz   =  id17_calc_crypto_frame_header_sz,
    .pf_parse_max_data                =  id17_parse_max_data,
    .pf_gen_max_data_frame            =  id17_gen_max_data_frame,
    .pf_max_data_frame_size           =  id17_max_data_frame_size,
    .pf_parse_new_conn_id             =  id17_parse_new_conn_id,
    .pf_gen_stream_blocked_frame      =  id17_gen_stream_blocked_frame,
    .pf_parse_stream_blocked_frame    =  id17_parse_stream_blocked_frame,
    .pf_stream_blocked_frame_size     =  id17_stream_blocked_frame_size,
    .pf_gen_max_stream_data_frame     =  id17_gen_max_stream_data_frame,
    .pf_parse_max_stream_data_frame   =  id17_parse_max_stream_data_frame,
    .pf_max_stream_data_frame_size    =  id17_max_stream_data_frame_size,
    .pf_parse_stop_sending_frame      =  id17_parse_stop_sending_frame,
    .pf_parse_new_token_frame         =  id17_parse_new_token_frame,
    .pf_new_connection_id_frame_size  =  id17_new_connection_id_frame_size,
    .pf_gen_new_connection_id_frame   =  id17_gen_new_connection_id_frame,
    .pf_parse_retire_cid_frame        =  id17_parse_retire_cid_frame,
    .pf_gen_retire_cid_frame          =  id17_gen_retire_cid_frame,
    .pf_retire_cid_frame_size         =  id17_retire_cid_frame_size,
    .pf_parse_max_streams_frame       =  id17_parse_max_streams_frame,
};
