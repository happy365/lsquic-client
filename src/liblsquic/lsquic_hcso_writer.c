/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hcso_writer.c - write to outgoing HTTP Control Stream
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_sfcw.h"
#include "lsquic_hq.h"
#include "lsquic_varint.h"
#include "lsquic_hash.h"
#include "lsquic_stream.h"
#include "lsquic_frab_list.h"
#include "lsquic_varint.h"
#include "lsquic_byteswap.h"
#include "lsquic_hq.h"
#include "lsquic_hcso_writer.h"

#define LSQUIC_LOGGER_MODULE LSQLM_HCSO_WRITER
#define LSQUIC_LOG_CONN_ID \
                    lsquic_conn_log_cid(lsquic_stream_conn(writer->how_stream))
#include "lsquic_logger.h"

static lsquic_stream_ctx_t *
hcso_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct hcso_writer *writer = stream_if_ctx;
    writer->how_stream = stream;
    lsquic_frab_list_init(&writer->how_fral, 0x100, NULL, NULL, NULL);
    if (0 != lsquic_frab_list_write(&writer->how_fral,
                                (unsigned char[]) { HQUST_CONTROL } , 1))
    {
        LSQ_INFO("cannot write to frab list");
        /* TODO: abort connection */
    }
    LSQ_DEBUG("create HTTP Control Stream Writer");
    lsquic_stream_wantwrite(stream, 1);
    return stream_if_ctx;
}


int
lsquic_hcso_write_settings (struct hcso_writer *writer,
                        const struct lsquic_engine_settings *settings,
                        int is_server)
{
    unsigned char *p;
    unsigned bits;
    int was_empty;
    unsigned char buf[1 /* Frame size */ + /* Frame type */ 1
        /* There are maximum four settings that need to be written out and
         * each value can be encoded in maximum 8 bytes:
         */
        + 4 * (2 + 8) ];

    p = buf + 1;
    *p++ = HQFT_SETTINGS;

    if (is_server)
        if (settings->es_h3_placeholders != HQ_DF_NUM_PLACEHOLDERS)
        {
            /* Write out SETTINGS_NUM_PLACEHOLDERS */
            memcpy(p, (unsigned char []){ 0, HQSID_NUM_PLACEHOLDERS, }, 2);
            p += 2;
            bits = vint_val2bits(settings->es_h3_placeholders);
            vint_write(p, settings->es_h3_placeholders, bits, 1 << bits);
            p += 1 << bits;
        }

    if (settings->es_max_header_list_size != HQ_DF_MAX_HEADER_LIST_SIZE)
    {
        /* Write out SETTINGS_MAX_HEADER_LIST_SIZE */
        memcpy(p, (unsigned char []){ 0, HQSID_MAX_HEADER_LIST_SIZE, }, 2);
        p += 2;
        bits = vint_val2bits(settings->es_max_header_list_size);
        vint_write(p, settings->es_max_header_list_size, bits, 1 << bits);
        p += 1 << bits;
    }

    if (settings->es_qpack_dec_max_size != HQ_DF_HEADER_TABLE_SIZE)
    {
        /* Write out SETTINGS_HEADER_TABLE_SIZE */
        memcpy(p, (unsigned char []){ 0, HQSID_HEADER_TABLE_SIZE, }, 2);
        p += 2;
        bits = vint_val2bits(settings->es_qpack_dec_max_size);
        vint_write(p, settings->es_qpack_dec_max_size, bits, 1 << bits);
        p += 1 << bits;
    }

    if (settings->es_qpack_dec_max_blocked != HQ_DF_QPACK_BLOCKED_STREAMS)
    {
        /* Write out SETTINGS_QPACK_BLOCKED_STREAMS */
        memcpy(p, (unsigned char []){ 0, HQSID_QPACK_BLOCKED_STREAMS, }, 2);
        p += 2;
        bits = vint_val2bits(settings->es_qpack_dec_max_size);
        vint_write(p, settings->es_qpack_dec_max_blocked, bits, 1 << bits);
        p += 1 << bits;
    }

    *buf = p - buf - 2;

    was_empty = lsquic_frab_list_empty(&writer->how_fral);

    if (0 != lsquic_frab_list_write(&writer->how_fral, buf, p - buf))
    {
        LSQ_INFO("cannot write SETTINGS frame to frab list");
        return -1;
    }

    if (was_empty)
        lsquic_stream_wantwrite(writer->how_stream, 1);

    LSQ_DEBUG("generated %u-byte SETTINGS frame", (unsigned) (p - buf));
    return 0;
}


static void
hcso_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct hcso_writer *const writer = (void *) ctx;
    struct lsquic_reader reader = {
        .lsqr_read  = lsquic_frab_list_read,
        .lsqr_size  = lsquic_frab_list_size,
        .lsqr_ctx   = &writer->how_fral
    };
    ssize_t nw;

    nw = lsquic_stream_writef(stream, &reader);
    if (nw >= 0)
    {
        LSQ_DEBUG("wrote %zd bytes to stream", nw);
        (void) lsquic_stream_flush(stream);
        if (lsquic_frab_list_empty(&writer->how_fral))
            lsquic_stream_wantwrite(stream, 0);
    }
    else
    {
        /* TODO: abort connection */
        LSQ_WARN("cannot write to stream: %s", strerror(errno));
        lsquic_stream_wantwrite(stream, 0);
    }
}


static void
hcso_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct hcso_writer *writer = (void *) ctx;
    LSQ_DEBUG("close HTTP Control Stream Writer");
    lsquic_frab_list_cleanup(&writer->how_fral);
    writer->how_stream = NULL;
}


static void
hcso_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static const struct lsquic_stream_if hcso_if =
{
    .on_new_stream  = hcso_on_new,
    .on_read        = hcso_on_read,
    .on_write       = hcso_on_write,
    .on_close       = hcso_on_close,
};

const struct lsquic_stream_if *const lsquic_hcso_writer_if = &hcso_if;
