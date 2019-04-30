/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_parse_common.h
 */

#ifndef LSQUIC_PARSE_COMMON_H
#define LSQUIC_PARSE_COMMON_H 1

struct lsquic_packet_in;
struct packin_parse_state;

struct packin_parse_state {
    const unsigned char     *pps_p;      /* Pointer to packet number */
    unsigned                 pps_nbytes; /* Number of bytes in packet number */
};

int
lsquic_parse_packet_in_begin (struct lsquic_packet_in *,
                size_t length, int is_server, unsigned cid_len,
                struct packin_parse_state *);

int
lsquic_ID18_parse_packet_in_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

int
lsquic_Q044_parse_packet_in_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

int
lsquic_Q046_parse_packet_in_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

int
lsquic_ID18_parse_packet_in_long_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

int
lsquic_ID18_parse_packet_in_short_begin (struct lsquic_packet_in *,
            size_t length, int is_server, unsigned cid_len,
            struct packin_parse_state *);

/* Instead of just -1 like CHECK_SPACE(), this macro returns the number
 * of bytes needed.
 */
#define CHECK_STREAM_SPACE(need, pstart, pend) do {                 \
    if ((intptr_t) (need) > ((pend) - (pstart))) {                  \
        return -((int) (need));                                     \
    }                                                               \
} while (0)

#endif
