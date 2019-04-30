/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_in.h"
#include "lsquic_parse_common.h"
#include "lsquic_parse.h"
#include "lsquic_enc_sess.h"
#include "lsquic_version.h"




/* This function does not support Q044 and Q046 */
int
lsquic_parse_packet_in_begin (lsquic_packet_in_t *packet_in, size_t length,
            int is_server, unsigned cid_len, struct packin_parse_state *state)
{
    if (length > 0)
    {
        switch (packet_in->pi_data[0] & 0xC0)
        {
        /* XXX Revisit this: does this logic check out? */
        case 0xC0:
        case 0x80:
            return lsquic_ID18_parse_packet_in_long_begin(packet_in,
                                        length, is_server, cid_len, state);
        case 0x00:
            return lsquic_gquic_parse_packet_in_begin(packet_in, length,
                                                    is_server, cid_len, state);
        default:
            return lsquic_ID18_parse_packet_in_short_begin(packet_in,
                                        length, is_server, cid_len, state);
        }
    }
    else
        return -1;
}


int
lsquic_ID18_parse_packet_in_begin (struct lsquic_packet_in *packet_in,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *state)
{
    if (length > 0)
    {
        if (0 == (packet_in->pi_data[0] & 0x80))
            return lsquic_ID18_parse_packet_in_short_begin(packet_in, length,
                                                    is_server, cid_len, state);
        else
            return lsquic_ID18_parse_packet_in_long_begin(packet_in, length,
                                                    is_server, cid_len, state);
    }
    else
        return -1;
}


int
lsquic_Q044_parse_packet_in_begin (struct lsquic_packet_in *packet_in,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *state)
{
    assert(!is_server);
    assert(cid_len == GQUIC_CID_LEN);
    if (length > 0)
    {
        if (0 == (packet_in->pi_data[0] & 0x80))
            return lsquic_Q044_parse_packet_in_short_begin(packet_in, length,
                                                    is_server, cid_len, state);
        else
            return lsquic_Q044_parse_packet_in_long_begin(packet_in, length,
                                                    is_server, cid_len, state);
    }
    else
        return -1;
}


int
lsquic_Q046_parse_packet_in_begin (struct lsquic_packet_in *packet_in,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *state)
{
    assert(!is_server);
    assert(cid_len == GQUIC_CID_LEN);
    if (length > 0)
    {
        if (0 == (packet_in->pi_data[0] & 0x80))
            return lsquic_ID18_parse_packet_in_short_begin(packet_in, length,
                                    is_server, is_server ? cid_len : 0, state);
        else
            return lsquic_Q044_parse_packet_in_long_begin(packet_in, length,
                                                    is_server, cid_len, state);
    }
    else
        return -1;
}


/* See [draft-ietf-quic-tls-19], Section 4 */
const enum quic_ft_bit lsquic_legal_frames_by_level[N_ENC_LEVS] =
{
    [ENC_LEV_CLEAR] = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_EARLY] = QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE | QUIC_FTBIT_PATH_RESPONSE
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID | QUIC_FTBIT_NEW_TOKEN,
    [ENC_LEV_INIT]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK| QUIC_FTBIT_CONNECTION_CLOSE,
    [ENC_LEV_FORW]  = QUIC_FTBIT_CRYPTO | QUIC_FTBIT_PADDING | QUIC_FTBIT_PING
                    | QUIC_FTBIT_ACK | QUIC_FTBIT_CONNECTION_CLOSE
                    | QUIC_FTBIT_STREAM | QUIC_FTBIT_RST_STREAM
                    | QUIC_FTBIT_BLOCKED
                    | QUIC_FTBIT_MAX_DATA | QUIC_FTBIT_MAX_STREAM_DATA
                    | QUIC_FTBIT_MAX_STREAMS | QUIC_FTBIT_STREAM_BLOCKED
                    | QUIC_FTBIT_STREAMS_BLOCKED
                    | QUIC_FTBIT_NEW_CONNECTION_ID | QUIC_FTBIT_STOP_SENDING
                    | QUIC_FTBIT_PATH_CHALLENGE | QUIC_FTBIT_PATH_RESPONSE
                    | QUIC_FTBIT_RETIRE_CONNECTION_ID | QUIC_FTBIT_NEW_TOKEN,
};
