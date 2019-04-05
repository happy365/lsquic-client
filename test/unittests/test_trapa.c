/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * test_trapa.c -- Test transport parameters.
 */

#include <assert.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_sizes.h"
#include "lsquic_logger.h"
#include "lsquic_trans_params.h"

#define ENC_BUF_SZ 0x1000

struct trapa_test
{
    int                         line;
    enum {
        TEST_ENCODE = 1 << 0,
        TEST_DECODE = 1 << 1,
    }                           flags;
    struct transport_params     params;
    size_t                      enc_len, dec_len;
    int                         expect_decode_err;
    unsigned char               encoded[ENC_BUF_SZ];
};

static const struct trapa_test tests[] =
{

    {
        .line   = __LINE__,
        .flags  = TEST_ENCODE,
        .params = {
            TP_DEFAULT_VALUES,
        },
        .enc_len = 0,
        .dec_len = 0,
        .encoded =
    /* Trailer to make the end easily visible in gdb: */
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    },

    {
        .line   = __LINE__,
        .flags  = TEST_ENCODE,
        .params = {
            .tp_flags   = 0,
            .tp_init_max_stream_data_bidi_local = 0x12348877,
            .tp_init_max_data = 0xAABB,
            .tp_idle_timeout = 10 * 1000,
            .tp_max_ack_delay = TP_DEF_MAX_ACK_DELAY,
        },
        .enc_len = 32,
        .dec_len = 32,
        .encoded =
     /* Idle timeout */     "\x00\x01\x00\x02\x67\x10"
     /* Packet size */      "\x00\x03\x00\x01\x00"
     /* Max data */         "\x00\x04\x00\x04\x80\x00\xAA\xBB"
     /* Bidi local */       "\x00\x05\x00\x04\x92\x34\x88\x77"
     /* Ack delay exp */    "\x00\x0A\x00\x01\x00"
    /* Trailer to make the end easily visible in gdb: */
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    },

    {
        .line   = __LINE__,
        .flags  = TEST_DECODE,
        .dec_len = 1,
        .expect_decode_err = 1,
    },

    {
        .line   = __LINE__,
        .flags  = TEST_DECODE,
        .dec_len = 3,
        .expect_decode_err = 1,
        .encoded = "\x00\x04",
    },


    {
        .line   = __LINE__,
        .flags  = TEST_DECODE,
        .params = {
            TP_DEFAULT_VALUES,
            .tp_flags = TRAPA_SERVER,
            .tp_init_max_data = 0x123456,
            .tp_init_max_stream_data_bidi_local = 0xABCDEF88,
            .tp_disable_migration = 1,
            .tp_max_packet_size = 0x333,
        },
        .enc_len = 30,
        .dec_len = 30,
        .encoded =
     /* Packet size */      "\x00\x03\x00\x02\x43\x33"
     /* Max data */         "\x00\x04\x00\x04\x80\x12\x34\x56"
     /* Bidi local */       "\x00\x05\x00\x08\xC0\x00\x00\x00\xAB\xCD\xEF\x88"
     /* Migration */        "\x00\x0C\x00\x00"
    /* Trailer to make the end easily visible in gdb: */
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    },

    /* Test server preferred address. */
    {
        .line   = __LINE__,
        .flags  = TEST_DECODE,
        .params = {
            TP_DEFAULT_VALUES,
            .tp_flags = TRAPA_SERVER | TRAPA_PREFERRED_ADDR,
            .tp_max_ack_delay = 25,
            .tp_max_packet_size = 0x333,
            .tp_preferred_address = {
                .ipv4_addr = "\x01\x02\x03\x04",
                .ipv4_port = 0x1234,
                .ipv6_addr = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                .ipv6_port = 0x9001,
                .cid = { .len = 11, .idbuf = "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A", },
                .srst = "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F",
            },
        },
        .enc_len = 0x3E,
        .dec_len = 0x3E,
        .encoded =
     /* Preferred Address */"\x00\x0D"
                            "\x00\x34"
                            "\x01\x02\x03\x04"
                            "\x12\x34"
                            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                            "\x90\x01"
                            "\x0B"  /* CID len */
                            "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A"
                            "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F"
     /* Packet size */      "\x00\x03\x00\x02\x43\x33"
    /* Trailer to make the end easily visible in gdb: */
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    },

};


static int
params_are_equal (const struct transport_params *a,
                  const struct transport_params *b)
{
    return 0 == memcmp(a, b, sizeof(*a));
}


static void
run_test (const struct trapa_test *test)
{
    struct transport_params decoded_params;
    int s;
    unsigned char buf[ENC_BUF_SZ];

    if (test->flags & TEST_ENCODE)
    {
        s = lsquic_tp_encode(&test->params, buf, sizeof(buf));
        assert(s >= 0);
        assert((size_t) s == test->enc_len);
        assert(0 == memcmp(test->encoded, buf, s));
    }

    if (test->flags & TEST_DECODE)
    {
        s = lsquic_tp_decode(test->encoded, test->dec_len, &decoded_params);
        if (!test->expect_decode_err)
        {
            assert(s == 0);
            s = params_are_equal(&test->params, &decoded_params);
            assert(s);
        }
        else
            assert(s < 0);
    }
}


static void
decode_file (const char *name)
{
    FILE *file;
    size_t nread;
    int s;
    struct transport_params params;
    unsigned char buf[0x1000];

    file = fopen(name, "rb");
    if (!file)
    {
        perror("fopen");
        exit(1);
    }

    nread = fread(buf, 1, sizeof(buf), file);

    s = lsquic_tp_decode(buf, nread, params);

    fclose(file);

    printf("decoded params from %s: %d (%s)\n", name, s, s == 0 ? "OK" : "FAIL");
}


int
main (int argc, char **argv)
{
    unsigned i;
    int opt;

    while (-1 != (opt = getopt(argc, argv, "d:l:")))
    {
        switch (opt)
        {
        case 'd':
            decode_file(optarg);
            return 0;
        case 'l':
            lsquic_log_to_fstream(stderr, 0);
            lsquic_logger_lopt(optarg);
            break;
        default:
            exit(1);
        }
    }

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
        run_test(&tests[i]);

    return 0;
}
