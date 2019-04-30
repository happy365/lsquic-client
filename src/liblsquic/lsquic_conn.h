/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_conn.h -- Connection interface
 *
 */
#ifndef LSQUIC_CONN_H
#define LSQUIC_CONN_H

#include <sys/queue.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <ws2ipdef.h>
#endif

struct lsquic_conn;
struct lsquic_engine_public;
struct lsquic_packet_out;
struct lsquic_packet_in;
struct sockaddr;
struct parse_funcs;
struct attq_elem;
#if LSQUIC_CONN_STATS
struct conn_stats;
#endif

enum lsquic_conn_flags {
    LSCONN_TICKED         = (1 << 0),
    LSCONN_HAS_OUTGOING   = (1 << 1),
    LSCONN_HASHED         = (1 << 2),
    LSCONN_HAS_PEER_SA    = (1 << 4),
    LSCONN_HAS_LOCAL_SA   = (1 << 5),
    LSCONN_HANDSHAKE_DONE = (1 << 6),
    LSCONN_CLOSING        = (1 << 7),
    LSCONN_PEER_GOING_AWAY= (1 << 8),
    LSCONN_TCID0          = (1 << 9),
    LSCONN_VER_SET        = (1 <<10),   /* cn_version is set */
    LSCONN_EVANESCENT     = (1 <<11),   /* evanescent connection */
    LSCONN_TICKABLE       = (1 <<12),   /* Connection is in the Tickable Queue */
    LSCONN_COI_ACTIVE     = (1 <<13),
    LSCONN_COI_INACTIVE   = (1 <<14),
    LSCONN_SEND_BLOCKED   = (1 <<15),   /* Send connection blocked frame */
    LSCONN_NEVER_TICKABLE = (1 <<17),   /* Do not put onto the Tickable Queue */
    LSCONN_ATTQ           = (1 <<19),
    LSCONN_IETF           = (1 <<23),
};

/* A connection may have things to send and be closed at the same time.
 */
enum tick_st {
    TICK_SEND    = (1 << 0),
    TICK_CLOSE   = (1 << 1),
};

#define TICK_QUIET 0

struct conn_iface
{
    enum tick_st
    (*ci_tick) (struct lsquic_conn *, lsquic_time_t now);

    void
    (*ci_packet_in) (struct lsquic_conn *, struct lsquic_packet_in *);

    /* Note: all packets "checked out" by calling this method should be
     * returned back to the connection via ci_packet_sent() or
     * ci_packet_not_sent() calls before the connection is ticked next.
     * The connection, in turn, should not perform any extra processing
     * (especially schedule more packets) during any of these method
     * calls.  This is because the checked out packets are not accounted
     * for by the congestion controller.
     */
    struct lsquic_packet_out *
    (*ci_next_packet_to_send) (struct lsquic_conn *, size_t);

    void
    (*ci_packet_sent) (struct lsquic_conn *, struct lsquic_packet_out *);

    void
    (*ci_packet_not_sent) (struct lsquic_conn *, struct lsquic_packet_out *);

    void
    (*ci_hsk_done) (struct lsquic_conn *, enum lsquic_hsk_status);

    void
    (*ci_destroy) (struct lsquic_conn *);

    int
    (*ci_is_tickable) (struct lsquic_conn *);

    lsquic_time_t
    (*ci_next_tick_time) (struct lsquic_conn *);

    int
    (*ci_can_write_ack) (struct lsquic_conn *);

    /* No return status: best effort */
    void
    (*ci_write_ack) (struct lsquic_conn *, struct lsquic_packet_out *);

#if LSQUIC_CONN_STATS
    const struct conn_stats *
    (*ci_get_stats) (struct lsquic_conn *);
#endif

    void
    (*ci_client_call_on_new) (struct lsquic_conn *);

    enum LSQUIC_CONN_STATUS
    (*ci_status) (struct lsquic_conn *, char *errbuf, size_t bufsz);

    unsigned
    (*ci_n_avail_streams) (const struct lsquic_conn *);

    unsigned
    (*ci_n_pending_streams) (const struct lsquic_conn *);

    unsigned
    (*ci_cancel_pending_streams) (struct lsquic_conn *, unsigned n);

    void
    (*ci_going_away) (struct lsquic_conn *);

    int
    (*ci_is_push_enabled) (struct lsquic_conn *);

    struct lsquic_stream *
    (*ci_get_stream_by_id) (struct lsquic_conn *, lsquic_stream_id_t stream_id);

    struct lsquic_engine *
    (*ci_get_engine) (struct lsquic_conn *);

    struct lsquic_conn_ctx *
    (*ci_get_ctx) (const struct lsquic_conn *);

    void
    (*ci_set_ctx) (struct lsquic_conn *, struct lsquic_conn_ctx *);

    void
    (*ci_make_stream) (struct lsquic_conn *);

    void
    (*ci_abort) (struct lsquic_conn *);

    void
    (*ci_retire_cid) (struct lsquic_conn *);

    void
    (*ci_close) (struct lsquic_conn *);

    void
    (*ci_stateless_reset) (struct lsquic_conn *);

    /* Use this to abort the connection when unlikely errors occur */
    void
    (*ci_internal_error) (struct lsquic_conn *, const char *format, ...)
#if __GNUC__
            __attribute__((format(printf, 2, 3)))
#endif
    ;

    /* Abort connection with error */
    void
    (*ci_abort_error) (struct lsquic_conn *, int is_app, unsigned error_code,
                                                        const char *format, ...)
#if __GNUC__
            __attribute__((format(printf, 4, 5)))
#endif
    ;

    void
    (*ci_tls_alert) (struct lsquic_conn *, uint8_t);

};

#define LSCONN_CCE_BITS 3
#define LSCONN_MAX_CCES (1 << LSCONN_CCE_BITS)

struct conn_cid_elem
{
    struct lsquic_hash_elem     cce_hash_el;    /* Must be first element */
    lsquic_cid_t                cce_cid;
    unsigned                    cce_seqno;
    enum {
        CCE_USED        = 1 << 0,       /* Connection ID has been used */
        CCE_SEQNO       = 1 << 1,       /* cce_seqno is set (CIDs in Initial
                                         * packets have no sequence number).
                                         */
    }                           cce_flags;
};

struct lsquic_conn
{
    void                        *cn_peer_ctx;
    void                        *cn_enc_session;
    const struct enc_session_funcs_common
                                *cn_esf_c;
    union {
        const struct enc_session_funcs_gquic   *g;
        const struct enc_session_funcs_iquic   *i;
    }                            cn_esf;
#define cn_cid cn_cces[0].cce_cid
    lsquic_cid_t                 cn_dcid;
    STAILQ_ENTRY(lsquic_conn)    cn_next_closed_conn;
    TAILQ_ENTRY(lsquic_conn)     cn_next_ticked;
    TAILQ_ENTRY(lsquic_conn)     cn_next_out;
    const struct conn_iface     *cn_if;
    const struct parse_funcs    *cn_pf;
    struct attq_elem            *cn_attq_elem;
    lsquic_time_t                cn_last_sent;
    lsquic_time_t                cn_last_ticked;
    enum lsquic_conn_flags       cn_flags;
    enum lsquic_version          cn_version;
    struct conn_cid_elem        *cn_cces;   /* At least one is available */
    union {
        unsigned char       buf[sizeof(struct sockaddr_in6)];
        struct sockaddr     sa;
    }                            cn_peer_addr_u;
#define cn_peer_addr cn_peer_addr_u.buf
    unsigned short               cn_pack_size;
    unsigned char                cn_cces_mask;  /* Those that are set */
    unsigned char                cn_n_cces; /* Number of CCEs in cn_cces */
    unsigned char                cn_cur_cce_idx;
    unsigned char                cn_local_addr[sizeof(struct sockaddr_in6)];
#if LSQUIC_TEST
    struct conn_cid_elem         cn_cces_buf[8];
#define LSCONN_INITIALIZER_CID(lsconn_, cid_) { \
                .cn_cces = (lsconn_).cn_cces_buf, \
                .cn_cces_buf[0].cce_seqno = 0, \
                .cn_cces_buf[0].cce_flags = CCE_SEQNO, \
                .cn_cces_buf[0].cce_cid = (cid_), \
                .cn_n_cces = 8, .cn_cces_mask = 1, }
#define LSCONN_INITIALIZER_CIDLEN(lsconn_, len_) { \
                .cn_cces = (lsconn_).cn_cces_buf, \
                .cn_cces_buf[0].cce_seqno = 0, \
                .cn_cces_buf[0].cce_flags = CCE_SEQNO, \
                .cn_cces_buf[0].cce_cid = { .len = len_ }, \
                .cn_n_cces = 8, .cn_cces_mask = 1, }
#define LSCONN_INITIALIZE(lsconn_) do { \
            (lsconn_)->cn_cces = (lsconn_)->cn_cces_buf; \
            (lsconn_)->cn_n_cces = 8; (lsconn_)->cn_cces_mask = 1; } while (0)
#endif
};

#define END_OF_CCES(conn) ((conn)->cn_cces + (conn)->cn_n_cces)

#define CN_SCID(conn) (&(conn)->cn_cces[(conn)->cn_cur_cce_idx].cce_cid)

void
lsquic_conn_record_sockaddr (lsquic_conn_t *lconn, const struct sockaddr *local,
                                                  const struct sockaddr *peer);

int
lsquic_conn_decrypt_packet (lsquic_conn_t *lconn,
                    struct lsquic_engine_public *, struct lsquic_packet_in *);

int
lsquic_conn_copy_and_release_pi_data (const lsquic_conn_t *conn,
                    struct lsquic_engine_public *, struct lsquic_packet_in *);

void
lsquic_conn_retire_cid (lsquic_conn_t *lconn);

#define lsquic_conn_adv_time(c) ((c)->cn_attq_elem->ae_adv_time)

#if LSQUIC_CONN_STATS
struct conn_stats {
    /* All counters are of the same type, unsigned long, because we cast the
     * struct to an array to update the aggregate.
     */
    unsigned long           n_ticks;            /* How many time connection was ticked */
    struct {
        unsigned long       stream_data_sz;     /* Sum of all STREAM frames payload */
        unsigned long       stream_frames;      /* Number of STREAM frames */
        unsigned long       packets,            /* Incoming packets */
                            undec_packets,      /* Undecryptable packets */
                            dup_packets,        /* Duplicate packets */
                            err_packets;        /* Error packets(?) */
        unsigned long       n_acks,
                            n_acks_proc,
                            n_acks_merged[2];
        unsigned long       bytes;              /* Overall bytes in */
        unsigned long       headers_uncomp;     /* Sum of uncompressed header bytes */
        unsigned long       headers_comp;       /* Sum of compressed header bytes */
    }                   in;
    struct {
        unsigned long       stream_data_sz;
        unsigned long       stream_frames;
        unsigned long       acks;
        unsigned long       packets;            /* Number of sent packets */
        unsigned long       acked_via_loss;     /* Number of packets acked via loss record */
        unsigned long       retx_packets;       /* Number of retransmitted packets */
        unsigned long       bytes;              /* Overall bytes out */
        unsigned long       headers_uncomp;     /* Sum of uncompressed header bytes */
        unsigned long       headers_comp;       /* Sum of compressed header bytes */
    }                   out;
};
#endif

#define lsquic_conn_peer_ipv6(c) \
    (AF_INET6 == (c)->cn_peer_addr_u.sa.sa_family)

#endif
