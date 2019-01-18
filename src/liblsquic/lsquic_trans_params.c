/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_trans_params.c
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "lsquic_byteswap.h"
#include "lsquic_int_types.h"
#include "lsquic_types.h"
#include "lsquic_version.h"
#include "lsquic_sizes.h"
#include "lsquic_trans_params.h"
#include "lsquic_util.h"
#include "lsquic_varint.h"

#define LSQUIC_LOGGER_MODULE LSQLM_TRAPA
#include "lsquic_logger.h"


static const uint64_t def_vals[MAX_TPI + 1] =
{
    [TPI_MAX_PACKET_SIZE]                   =  TP_DEF_MAX_PACKET_SIZE,
    [TPI_ACK_DELAY_EXPONENT]                =  TP_DEF_ACK_DELAY_EXP,
    [TPI_INIT_MAX_STREAMS_UNI]              =  TP_DEF_INIT_MAX_STREAMS_UNI,
    [TPI_INIT_MAX_STREAMS_BIDI]             =  TP_DEF_INIT_MAX_STREAMS_BIDI,
    [TPI_INIT_MAX_DATA]                     =  TP_DEF_INIT_MAX_DATA,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]   =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_LOCAL,
    [TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]  =  TP_DEF_INIT_MAX_STREAM_DATA_BIDI_REMOTE,
    [TPI_INIT_MAX_STREAM_DATA_UNI]          =  TP_DEF_INIT_MAX_STREAM_DATA_UNI,
    [TPI_IDLE_TIMEOUT]                      =  TP_DEF_IDLE_TIMEOUT,
    [TPI_MAX_ACK_DELAY]                     =  TP_DEF_MAX_ACK_DELAY,
};


#define TP_OFF(name_) ((uint64_t *) &((struct transport_params *) 0 \
    )->tp_numerics_u.s.name_ - (uint64_t *) &((struct transport_params *) \
    0)->tp_numerics_u.s)

/* Map enum transport_params to index of tp_numerics_u.a; for numeric values only */
static const unsigned tpi2idx[MAX_TPI + 1] =
{
    [TPI_MAX_PACKET_SIZE]                   =  TP_OFF(max_packet_size),
    [TPI_ACK_DELAY_EXPONENT]                =  TP_OFF(ack_delay_exponent),
    [TPI_INIT_MAX_STREAMS_UNI]              =  TP_OFF(init_max_streams_uni),
    [TPI_INIT_MAX_STREAMS_BIDI]             =  TP_OFF(init_max_streams_bidi),
    [TPI_INIT_MAX_DATA]                     =  TP_OFF(init_max_data),
    [TPI_INIT_MAX_STREAM_DATA_BIDI_LOCAL]   =  TP_OFF(init_max_stream_data_bidi_local),
    [TPI_INIT_MAX_STREAM_DATA_BIDI_REMOTE]  =  TP_OFF(init_max_stream_data_bidi_remote),
    [TPI_INIT_MAX_STREAM_DATA_UNI]          =  TP_OFF(init_max_stream_data_uni),
    [TPI_IDLE_TIMEOUT]                      =  TP_OFF(idle_timeout),
    [TPI_MAX_ACK_DELAY]                     =  TP_OFF(max_ack_delay),
};

int
lsquic_tp_encode (const struct transport_params *params,
                  unsigned char *const buf, size_t bufsz)
{
    unsigned char *p;
    size_t need = 2;
    uint16_t u16;
    enum transport_param_id tpi;
    unsigned bits[MAX_TPI + 1];

    need += sizeof(params->tp_version_u.client.initial);

    for (tpi = 0; tpi <= MAX_TPI; ++tpi)
        if ((NUMERIC_TRANS_PARAMS & (1 << tpi))
                    && params->tp_numerics_u.a[tpi2idx[tpi]] != def_vals[tpi])
        {
            if (params->tp_numerics_u.a[tpi2idx[tpi]] < VINT_MAX_VALUE)
            {
                bits[tpi] = vint_val2bits(params->tp_numerics_u.a[tpi2idx[tpi]]);
                need += 4 + (1 << bits[tpi]);
            }
            else
            {
                LSQ_DEBUG("numeric value is too large");
                return -1;
            }
        }

    if (params->tp_disable_migration != TP_DEF_DISABLE_MIGRATION)
        need += 4 + 0;

    if (need > bufsz || need > UINT16_MAX)
    {
        errno = ENOBUFS;
        return -1;
    }

    p = buf;

#define WRITE_TO_P(src, len) do {                                       \
    memcpy(p, src, len);                                                \
    p += len;                                                           \
} while (0)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define WRITE_UINT_TO_P(val, width) do {                                \
    u##width = bswap_##width(val);                                      \
    WRITE_TO_P(&u##width, sizeof(u##width));                            \
} while (0)
#else
#define WRITE_UINT_TO_P(val, width) do {                                \
    u##width = val;                                                     \
    WRITE_TO_P(&u##width, sizeof(u##width));                            \
} while (0)
#endif

#define WRITE_PARAM_TO_P(tpidx, tpval, width) do {                      \
    WRITE_UINT_TO_P(tpidx, 16);                                         \
    WRITE_UINT_TO_P(width / 8, 16);                                     \
    if (width > 8)                                                      \
        WRITE_UINT_TO_P(tpval, width);                                  \
    else if (width)                                                     \
        *p++ = tpval;                                                   \
} while (0)

    {
        WRITE_TO_P(&params->tp_version_u.client.initial,
                            sizeof(params->tp_version_u.client.initial));
        LSQ_DEBUG("version: %02X%02X%02X%02X",
                    params->tp_version_u.client.buf[0],
                    params->tp_version_u.client.buf[1],
                    params->tp_version_u.client.buf[2],
                    params->tp_version_u.client.buf[3]);
    }
    WRITE_UINT_TO_P(need - 2 + buf - p, 16);

    for (tpi = 0; tpi <= MAX_TPI; ++tpi)
        if (NUMERIC_TRANS_PARAMS & (1 << tpi))
        {
            if (params->tp_numerics_u.a[tpi2idx[tpi]] != def_vals[tpi])
            {
                WRITE_UINT_TO_P(tpi, 16);
                WRITE_UINT_TO_P(1 << bits[tpi], 16);
                vint_write(p, params->tp_numerics_u.a[tpi2idx[tpi]], bits[tpi],
                                                                1 << bits[tpi]);
                p += 1 << bits[tpi];
            }
        }
        else
            switch (tpi)
            {
            case TPI_ORIGINAL_CONNECTION_ID:
            case TPI_STATELESS_RESET_TOKEN:
            case TPI_PREFERRED_ADDRESS:
                /* Client does not send these */
                break;
            case TPI_DISABLE_MIGRATION:
                if (params->tp_disable_migration != TP_DEF_DISABLE_MIGRATION)
                {
                    WRITE_UINT_TO_P(TPI_DISABLE_MIGRATION, 16);
                    WRITE_UINT_TO_P(0, 16);
                }
                break;
            default:
                assert(0);
                return -1;
            }

    assert(buf + need == p);
    return (int) (p - buf);

#undef WRITE_TO_P
#undef WRITE_UINT_TO_P
}


int
lsquic_tp_decode (const unsigned char *const buf, size_t bufsz,
                  struct transport_params *params)
{
    const unsigned char *p, *end;
    uint16_t len, param_id;
    uint8_t n_supported;
    unsigned set_of_ids;
    int s;

    p = buf;
    end = buf + bufsz;

    *params = TP_INITIALIZER();

    {
        if (end - p < 5)
            return -1;
        params->tp_flags |= TRAPA_SERVER;
        memcpy(&params->tp_version_u.server.negotiated, p, 4);
        p += 4;
        n_supported = *p++;
        if (n_supported)
        {
            if (n_supported & 3)
                return -1;
            if (end - p < n_supported)
                return -1;
            memcpy(params->tp_version_u.server.supported, p, n_supported);
            p += n_supported;
        }
        params->tp_version_u.server.n_supported = n_supported >> 2;
    }

    if (end - p < 2)
        return -1;
    READ_UINT(len, 16, p, 2);
    p += 2;
    if (len > end - p)
        return -1;
    end = p + len;

#define EXPECT_LEN(expected_len) do {                               \
    if (expected_len != len)                                        \
        return -1;                                                  \
} while (0)

    set_of_ids = 0;
    while (p < end)
    {
        READ_UINT(param_id, 16, p, 2);
        p += 2;
        READ_UINT(len, 16, p, 2);
        p += 2;
        if (len > end - p)
            return -1;
        /* If we need to support parameter IDs 31 and up, we will need to
         * change this code:
         */
        if (param_id > sizeof(set_of_ids) * 8)
            return -1;
        if (set_of_ids & (1 << param_id))
            return -1;
        set_of_ids |= 1 << param_id;
        if (NUMERIC_TRANS_PARAMS & (1u << param_id))
        {
            switch (len)
            {
            case 1:
            case 2:
            case 4:
            case 8:
                s = vint_read(p, p + len,
                            &params->tp_numerics_u.a[tpi2idx[param_id]]);
                if (s == len)
                {
                    p += s;
                    break;
                }
                else
                {
                    LSQ_DEBUG("cannot read the value of numeric transport "
                                        "param %u of length %u", param_id, len);
                    return -1;
                }
            default:
                LSQ_DEBUG("invalid length=%u for numeric transport parameter",
                                                                        len);
                return -1;
            }
        }
        else
        {
            switch (param_id)
            {
            case TPI_DISABLE_MIGRATION:
                EXPECT_LEN(0);
                params->tp_disable_migration = 1;
                break;
            case TPI_STATELESS_RESET_TOKEN:
                EXPECT_LEN(sizeof(params->tp_stateless_reset_token));
                memcpy(params->tp_stateless_reset_token, p,
                                    sizeof(params->tp_stateless_reset_token));
                params->tp_flags |= TRAPA_RESET_TOKEN;
                break;
            case TPI_ORIGINAL_CONNECTION_ID:
                if (len > MAX_CID_LEN)
                    return -1;
                memcpy(params->tp_original_cid.idbuf, p, len);
                params->tp_original_cid.len = len;
                params->tp_flags |= TRAPA_ORIGINAL_CID;
                break;
            case TPI_PREFERRED_ADDRESS:
                /* TODO: support preferred address */
                LSQ_ERROR("preferred address not supported");
                return -1;
            }
            p += len;
        }
    }

    if (p != end)
        return -1;

    return (int) (end - buf);
#undef EXPECT_LEN
}


void
lsquic_tp_to_str (const struct transport_params *params, char *buf, size_t sz)
{
    char *const end = buf + sz;
    int nw;
    char tok_str[sizeof(params->tp_stateless_reset_token) * 2 + 1];

#define SEMICOLON "; "
#define WRITE_ONE_PARAM(name, fmt) do {  \
    nw = snprintf(buf, end - buf, #name ": " fmt SEMICOLON, params->tp_##name); \
    buf += nw; \
    if (buf >= end) \
        return; \
} while (0)

    WRITE_ONE_PARAM(init_max_stream_data_bidi_local, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_stream_data_bidi_remote, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_stream_data_uni, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_data, "%"PRIu64);
    WRITE_ONE_PARAM(idle_timeout, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_streams_bidi, "%"PRIu64);
    WRITE_ONE_PARAM(init_max_streams_uni, "%"PRIu64);
    WRITE_ONE_PARAM(max_packet_size, "%"PRIu64);
    WRITE_ONE_PARAM(ack_delay_exponent, "%"PRIu64);
    WRITE_ONE_PARAM(disable_migration, "%hhd");
#undef SEMICOLON
#define SEMICOLON ""
    WRITE_ONE_PARAM(max_ack_delay, "%"PRIu64);
    if (params->tp_flags & TRAPA_RESET_TOKEN)
    {
        lsquic_hexstr(params->tp_stateless_reset_token,
            sizeof(params->tp_stateless_reset_token), tok_str, sizeof(tok_str));
        nw = snprintf(buf, end - buf, "; stateless_reset_token: %s", tok_str);
        buf += nw;
    }
    if (params->tp_flags & TRAPA_RESET_TOKEN)
    {
        char cidbuf_[MAX_CID_LEN * 2 + 1];
        nw = snprintf(buf, end - buf, "; original DCID (ODCID): %"CID_FMT,
                                        CID_BITS(&params->tp_original_cid));
        buf += nw;
    }

#undef SEMICOLON
#undef WRITE_ONE_PARAM
}


typedef char cant_overflow_supported[
       sizeof(((struct transport_params *)0)->tp_version_u.server.n_supported)
    <= sizeof(((struct transport_params *)0)->tp_version_u.server.supported)
    ? 1 : -1];
