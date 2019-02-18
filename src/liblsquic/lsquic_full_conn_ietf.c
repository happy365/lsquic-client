/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_full_conn_ietf.c -- IETF QUIC connection.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_ietf.h"
#include "lsquic_packet_in.h"
#include "lsquic_packet_out.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_rechist.h"
#include "lsquic_senhist.h"
#include "lsquic_cubic.h"
#include "lsquic_pacer.h"
#include "lsquic_sfcw.h"
#include "lsquic_conn_flow.h"
#include "lsquic_varint.h"
#include "lsquic_hq.h"
#include "lsquic_stream.h"
#include "lsquic_rtt.h"
#include "lsquic_conn_public.h"
#include "lsquic_send_ctl.h"
#include "lsquic_alarmset.h"
#include "lsquic_ver_neg.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_set.h"
#include "lsquic_sizes.h"
#include "lsquic_trans_params.h"
#include "lsquic_version.h"
#include "lsquic_parse.h"
#include "lsquic_util.h"
#include "lsquic_enc_sess.h"
#include "lsquic_ev_log.h"
#include "lsquic_malo.h"
#include "lsquic_frab_list.h"
#include "lsquic_hcso_writer.h"
#include "lsquic_hcsi_reader.h"
#include "lsqpack.h"
#include "lsquic_http1x_if.h"
#include "lsquic_qenc_hdl.h"
#include "lsquic_qdec_hdl.h"
#include "lsquic_full_conn.h"
#include "lsquic_h3_prio.h"
#include "lsquic_ietf.h"

#define LSQUIC_LOGGER_MODULE LSQLM_CONN
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(&conn->ifc_conn)
#include "lsquic_logger.h"

#define MAX_ANY_PACKETS_SINCE_LAST_ACK  20
#define MAX_RETR_PACKETS_SINCE_LAST_ACK 2
#define ACK_TIMEOUT                    (TP_DEF_MAX_ACK_DELAY * 1000)
#define TIME_BETWEEN_PINGS              15000000
#define IDLE_TIMEOUT                    30000000

#define MIN(a, b) ((a) < (b) ? (a) : (b))


enum ifull_conn_flags
{
    IFC_SERVER        = LSENG_SERVER,   /* Server mode */
    IFC_HTTP          = LSENG_HTTP,     /* HTTP mode */
    IFC_ACK_HAD_MISS  = 1 << 2,
#define IFC_BIT_ERROR 3
    IFC_ERROR         = 1 << IFC_BIT_ERROR,
    IFC_TIMED_OUT     = 1 << 4,
    IFC_ABORTED       = 1 << 5,
    IFC_HSK_FAILED    = 1 << 6,
    IFC_GOING_AWAY    = 1 << 7,
    IFC_CLOSING       = 1 << 8,   /* Closing */
    IFC_RECV_CLOSE    = 1 << 9,  /* Received CONNECTION_CLOSE frame */
    IFC_TICK_CLOSE    = 1 << 10,  /* We returned TICK_CLOSE */
    IFC_CREATED_OK    = 1 << 11,
    IFC_HAVE_SAVED_ACK= 1 << 12,
    IFC_ABORT_COMPLAINED
                      = 1 << 13,
    IFC_DCID_SET      = 1 << 14,
#define IFCBIT_ACK_QUED_SHIFT 15
    IFC_ACK_QUED_INIT = 1 << 15,
    IFC_ACK_QUED_HSK  = IFC_ACK_QUED_INIT << PNS_HSK,
    IFC_ACK_QUED_APP  = IFC_ACK_QUED_INIT << PNS_APP,
#define IFC_ACK_QUEUED (IFC_ACK_QUED_INIT|IFC_ACK_QUED_HSK|IFC_ACK_QUED_APP)
    IFC_HAVE_PEER_SET = 1 << 18,
    IFC_GOT_PRST      = 1 << 19,
    IFC_IGNORE_INIT   = 1 << 20,
    IFC_RETRIED       = 1 << 21,
    IFC_SWITCH_DCID   = 1 << 22, /* Perform DCID switch when a new CID becomes available */
};

enum send_flags
{
    SF_SEND_MAX_DATA    =  1 << 0,
    SF_SEND_PING        =  1 << 1,
    SF_SEND_PATH_RESP   =  1 << 2,
    SF_SEND_NEW_CID     =  1 << 3,
    SF_SEND_RETIRE_CID  =  1 << 4,
    SF_SEND_CONN_CLOSE  =  1 << 5,
};

#define IFC_IMMEDIATE_CLOSE_FLAGS \
            (IFC_TIMED_OUT|IFC_ERROR|IFC_ABORTED|IFC_HSK_FAILED|IFC_GOT_PRST)

#define MAX_ERRMSG 256

#define SET_ERRMSG(conn, ...) do {                                          \
    if (!(conn)->ifc_errmsg)                                                \
    {                                                                       \
        (conn)->ifc_errmsg = malloc(MAX_ERRMSG);                            \
        if ((conn)->ifc_errmsg)                                             \
            snprintf((conn)->ifc_errmsg, MAX_ERRMSG, __VA_ARGS__);          \
    }                                                                       \
} while (0)

#define ABORT_WITH_FLAG(conn, log_level, flag, ...) do {                    \
    SET_ERRMSG(conn, __VA_ARGS__);                                          \
    if (!((conn)->ifc_flags & IFC_ABORT_COMPLAINED))                        \
        LSQ_LOG(log_level, "Abort connection: " __VA_ARGS__);               \
    (conn)->ifc_flags |= flag|IFC_ABORT_COMPLAINED;                         \
} while (0)

#define ABORT_ERROR(...) \
    ABORT_WITH_FLAG(conn, LSQ_LOG_ERROR, IFC_ERROR, __VA_ARGS__)
#define ABORT_WARN(...) \
    ABORT_WITH_FLAG(conn, LSQ_LOG_WARN, IFC_ERROR, __VA_ARGS__)

#define CONN_ERR(app_error_, code_) (struct conn_err) { \
                            .app_error = (app_error_), .u.err = (code_), }

/* Use this for protocol errors; they do not need to be as loud as our own
 * internal errors.
 */
#define ABORT_QUIETLY(app_error, code, ...) do {                            \
    conn->ifc_error = CONN_ERR(app_error, code);                            \
    ABORT_WITH_FLAG(conn, LSQ_LOG_INFO, IFC_ERROR, __VA_ARGS__);            \
} while (0)


static enum stream_id_type
gen_sit (unsigned server, enum stream_dir sd)
{
    return (server > 0) | ((sd > 0) << SD_SHIFT);
}


struct stream_id_to_reset
{
    STAILQ_ENTRY(stream_id_to_reset)    sitr_next;
    lsquic_stream_id_t                  sitr_stream_id;
};

struct http_ctl_stream_in
{
    struct hcsi_reader  reader;
};

struct conn_err
{
    int                         app_error;
    union
    {
        enum trans_error_code   tec;
        enum http_error_code    hec;
        unsigned                err;
    }                           u;
};

struct ietf_full_conn
{
    struct lsquic_conn          ifc_conn;
    struct conn_cid_elem        ifc_cces[8];
    struct lsquic_rechist       ifc_rechist[N_PNS];
    struct lsquic_send_ctl      ifc_send_ctl;
    struct lsquic_stream       *ifc_crypto_streams[N_ENC_LEVS];
    struct lsquic_stream       *ifc_stream_hcsi;    /* HTTP Control Stream Incoming */
    struct lsquic_stream       *ifc_stream_hcso;    /* HTTP Control Stream Outgoing */
    struct lsquic_conn_public   ifc_pub;
    lsquic_alarmset_t           ifc_alset;
    struct lsquic_set64         ifc_closed_stream_ids[N_SITS];
    lsquic_stream_id_t          ifc_n_created_streams[N_SDS];
    lsquic_stream_id_t          ifc_max_allowed_stream_id[N_SITS];
    uint64_t                    ifc_max_stream_data_uni;
    enum ifull_conn_flags       ifc_flags;
    enum send_flags             ifc_send_flags;
    struct conn_err             ifc_error;
    unsigned                    ifc_n_delayed_streams;
    unsigned                    ifc_n_cons_unretx;
    const struct lsquic_stream_if
                               *ifc_stream_if;
    void                       *ifc_stream_ctx;
    char                       *ifc_errmsg;
    struct lsquic_engine_public
                               *ifc_enpub;
    const struct lsquic_engine_settings
                               *ifc_settings;
    lsquic_conn_ctx_t          *ifc_conn_ctx;
    struct ver_neg              ifc_ver_neg;
    struct transport_params     ifc_peer_param;
    STAILQ_HEAD(, stream_id_to_reset)
                                ifc_stream_ids_to_reset;
    struct short_ack_info       ifc_saved_ack_info;
    lsquic_time_t               ifc_saved_ack_received;
    lsquic_packno_t             ifc_max_ack_packno[N_PNS];
    uint64_t                    ifc_path_chal;
    lsquic_stream_id_t          ifc_max_peer_stream_id;
    struct {
        uint32_t    max_stream_send;
        uint8_t     ack_exp;
    }                           ifc_cfg;
    int                       (*ifc_process_incoming_packet)(
                                                struct ietf_full_conn *,
                                                struct lsquic_packet_in *);
    /* Number ackable packets received since last ACK was sent: */
    unsigned                    ifc_n_slack_akbl[N_PNS];
    uint64_t                    ifc_ecn_counts_in[N_PNS][4];
    uint64_t                    ifc_ecn_counts_out[N_PNS][4];
    struct hcso_writer          ifc_hcso;
    struct http_ctl_stream_in   ifc_hcsi;
    struct qpack_enc_hdl        ifc_qeh;
    struct qpack_dec_hdl        ifc_qdh;
    struct {
        uint64_t    header_table_size,
                    num_placeholders,
                    max_header_list_size,
                    qpack_blocked_streams;
    }                           ifc_peer_hq_settings;
    struct dcid_elem           *ifc_dces[8];
    TAILQ_HEAD(, dcid_elem)     ifc_to_retire;
    unsigned                    ifc_scid_seqno;
    /* Last 8 packets had ECN markings? */
    uint8_t                     ifc_incoming_ecn;
};

static const struct conn_iface *ietf_full_conn_iface_ptr;

static int
process_incoming_packet_verneg (struct ietf_full_conn *,
                                                struct lsquic_packet_in *);

static int
process_incoming_packet_fast (struct ietf_full_conn *,
                                                struct lsquic_packet_in *);

static void
ietf_full_conn_ci_packet_in (struct lsquic_conn *, struct lsquic_packet_in *);

static void
handshake_ok (struct lsquic_conn *);

static unsigned
ietf_full_conn_ci_n_avail_streams (const struct lsquic_conn *);


static unsigned
highest_bit_set (unsigned sz)
{
#if __GNUC__
    unsigned clz = __builtin_clz(sz);
    return 31 - clz;
#else
    unsigned n, y;
    n = 32;
    y = sz >> 16;   if (y) { n -= 16; sz = y; }
    y = sz >>  8;   if (y) { n -=  8; sz = y; }
    y = sz >>  4;   if (y) { n -=  4; sz = y; }
    y = sz >>  2;   if (y) { n -=  2; sz = y; }
    y = sz >>  1;   if (y) return 31 - n + 2;
    return 31 - n + sz;
#endif
}


static void
set_versions (struct ietf_full_conn *conn, unsigned versions)
{
    conn->ifc_ver_neg.vn_supp = versions;
    conn->ifc_ver_neg.vn_ver  = highest_bit_set(versions);
    conn->ifc_ver_neg.vn_buf  = lsquic_ver2tag(conn->ifc_ver_neg.vn_ver);
    conn->ifc_conn.cn_version = conn->ifc_ver_neg.vn_ver;
}


static void
init_ver_neg (struct ietf_full_conn *conn, unsigned versions)
{
    set_versions(conn, versions);
    conn->ifc_ver_neg.vn_tag   = &conn->ifc_ver_neg.vn_buf;
    conn->ifc_ver_neg.vn_state = VN_START;
}


static void
ack_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                        lsquic_time_t now)
{
    struct ietf_full_conn *conn = ctx;
    enum packnum_space pns = al_id - AL_ACK_INIT;
    LSQ_DEBUG("%s ACK timer expired (%"PRIu64" < %"PRIu64"): ACK queued",
        lsquic_pns2str[pns], expiry, now);
    conn->ifc_flags |= IFC_ACK_QUED_INIT << pns;
}


static void
idle_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                            lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("connection timed out");
    conn->ifc_flags |= IFC_TIMED_OUT;
}


static void
handshake_alarm_expired (enum alarm_id al_id, void *ctx,
                                    lsquic_time_t expiry, lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("connection timed out: handshake timed out");
    conn->ifc_flags |= IFC_TIMED_OUT;
}


static void
ping_alarm_expired (enum alarm_id al_id, void *ctx, lsquic_time_t expiry,
                                                            lsquic_time_t now)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) ctx;
    LSQ_DEBUG("Ping alarm rang: schedule PING frame to be generated");
    conn->ifc_send_flags |= SF_SEND_PING;
}


static ssize_t
crypto_stream_write (void *stream, const void *buf, size_t len)
{
    return lsquic_stream_write(stream, buf, len);
}


static int
crypto_stream_flush (void *stream)
{
    return lsquic_stream_flush(stream);
}


static ssize_t
crypto_stream_readf (void *stream,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx)
{
    return lsquic_stream_readf(stream, readf, ctx);
}


static int
crypto_stream_wantwrite (void *stream, int is_want)
{
    return lsquic_stream_wantwrite(stream, is_want);
}


static int
crypto_stream_wantread (void *stream, int is_want)
{
    return lsquic_stream_wantread(stream, is_want);
}


static enum enc_level
crypto_stream_enc_level (void *streamp)
{
    const struct lsquic_stream *stream = streamp;
    return crypto_level(stream);
}


static const struct crypto_stream_if crypto_stream_if =
{
    .csi_write      = crypto_stream_write,
    .csi_flush      = crypto_stream_flush,
    .csi_readf      = crypto_stream_readf,
    .csi_wantwrite  = crypto_stream_wantwrite,
    .csi_wantread   = crypto_stream_wantread,
    .csi_enc_level  = crypto_stream_enc_level,
};


static const struct lsquic_stream_if *unicla_if_ptr;


static lsquic_stream_id_t
generate_stream_id (struct ietf_full_conn *conn, enum stream_dir sd)
{
    lsquic_stream_id_t id;

    id = conn->ifc_n_created_streams[sd]++;
    return id << SIT_SHIFT
         | sd << SD_SHIFT
        ;
}


static lsquic_stream_id_t
avail_streams_count (const struct ietf_full_conn *conn, int server,
                                                            enum stream_dir sd)
{
    enum stream_id_type sit;
    lsquic_stream_id_t max_count;

    sit = gen_sit(server, sd);
    max_count = conn->ifc_max_allowed_stream_id[sit] >> SIT_SHIFT;
    if (max_count >= conn->ifc_n_created_streams[sd])
        return max_count - conn->ifc_n_created_streams[sd];
    else
    {
        assert(0);
        return 0;
    }
}


/* If `priority' is negative, this means that the stream is critical */
static int
create_uni_stream_out (struct ietf_full_conn *conn, int priority,
        const struct lsquic_stream_if *stream_if, void *stream_if_ctx)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;

    /* TODO: check that we don't go over peer-advertized limit */
    stream_id = generate_stream_id(conn, SD_UNI);
    stream = lsquic_stream_new(stream_id, &conn->ifc_pub, stream_if,
                stream_if_ctx, 0, conn->ifc_max_stream_data_uni,
                SCF_IETF | (priority < 0 ? SCF_CRITICAL : 0));
    if (!stream)
        return -1;
    if (!lsquic_hash_insert(conn->ifc_pub.all_streams, &stream->id,
                            sizeof(stream->id), stream, &stream->sm_hash_el))
    {
        lsquic_stream_destroy(stream);
        return -1;
    }
    if (priority >= 0)
        lsquic_stream_set_priority_internal(stream, priority);
    lsquic_stream_call_on_new(stream);
    return 0;
}


static int
create_ctl_stream_out (struct ietf_full_conn *conn)
{
    return create_uni_stream_out(conn, -1,
                                    lsquic_hcso_writer_if, &conn->ifc_hcso);
}


static int
create_qenc_stream_out (struct ietf_full_conn *conn)
{
    return create_uni_stream_out(conn, -1,
                                    lsquic_qeh_enc_sm_out_if, &conn->ifc_qeh);
}


static int
create_qdec_stream_out (struct ietf_full_conn *conn)
{
    return create_uni_stream_out(conn, -1,
                                    lsquic_qdh_dec_sm_out_if, &conn->ifc_qdh);
}


static int
create_bidi_stream_out (struct ietf_full_conn *conn)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;

    stream_id = generate_stream_id(conn, SD_BIDI);
    stream = lsquic_stream_new(stream_id, &conn->ifc_pub, conn->ifc_stream_if,
                conn->ifc_stream_ctx,
                conn->ifc_settings->es_init_max_stream_data_bidi_local,
                conn->ifc_cfg.max_stream_send, SCF_IETF
                | (conn->ifc_flags & IFC_HTTP ? SCF_HTTP : 0));
    if (!stream)
        return -1;
    if (!lsquic_hash_insert(conn->ifc_pub.all_streams, &stream->id,
                            sizeof(stream->id), stream, &stream->sm_hash_el))
    {
        lsquic_stream_destroy(stream);
        return -1;
    }
    lsquic_stream_call_on_new(stream);
    return 0;
}


static int
ietf_full_conn_init (struct ietf_full_conn *conn,
           struct lsquic_engine_public *enpub,
           const struct lsquic_stream_if *stream_if, void *stream_if_ctx,
           unsigned flags)
{
    if (enpub->enp_settings.es_scid_len)
        assert(CN_SCID(&conn->ifc_conn)->len);
    conn->ifc_stream_if = stream_if;
    conn->ifc_stream_ctx = stream_if_ctx;
    conn->ifc_enpub = enpub;
    conn->ifc_settings = &enpub->enp_settings;
    conn->ifc_pub.lconn = &conn->ifc_conn;
    conn->ifc_pub.send_ctl = &conn->ifc_send_ctl;
    conn->ifc_pub.enpub = enpub;
    conn->ifc_pub.mm = &enpub->enp_mm;
    TAILQ_INIT(&conn->ifc_pub.sending_streams);
    TAILQ_INIT(&conn->ifc_pub.read_streams);
    TAILQ_INIT(&conn->ifc_pub.write_streams);
    TAILQ_INIT(&conn->ifc_pub.service_streams);
    STAILQ_INIT(&conn->ifc_stream_ids_to_reset);
    TAILQ_INIT(&conn->ifc_to_retire);

    lsquic_alarmset_init(&conn->ifc_alset, &conn->ifc_conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_IDLE, idle_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK_APP, ack_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK_INIT, ack_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_ACK_HSK, ack_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_PING, ping_alarm_expired, conn);
    lsquic_alarmset_init_alarm(&conn->ifc_alset, AL_HANDSHAKE, handshake_alarm_expired, conn);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_INIT], &conn->ifc_conn, 1);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_HSK], &conn->ifc_conn, 1);
    lsquic_rechist_init(&conn->ifc_rechist[PNS_APP], &conn->ifc_conn, 1);
    lsquic_send_ctl_init(&conn->ifc_send_ctl, &conn->ifc_alset, enpub,
        &conn->ifc_ver_neg, &conn->ifc_pub, SC_IETF|SC_NSTP);
    lsquic_cfcw_init(&conn->ifc_pub.cfcw, &conn->ifc_pub,
                                                conn->ifc_settings->es_cfcw);
    conn->ifc_pub.all_streams = lsquic_hash_create();
    if (!conn->ifc_pub.all_streams)
        goto err0;
    conn->ifc_pub.u.ietf.prio_tree = lsquic_prio_tree_new(&conn->ifc_conn,
            flags & IFC_SERVER ? conn->ifc_settings->es_h3_placeholders : 0);
    if (!conn->ifc_pub.u.ietf.prio_tree)
        goto err1;
    conn->ifc_pub.u.ietf.qeh = &conn->ifc_qeh;
    conn->ifc_pub.u.ietf.qdh = &conn->ifc_qdh;

    conn->ifc_peer_hq_settings.header_table_size     = HQ_DF_HEADER_TABLE_SIZE;
    conn->ifc_peer_hq_settings.num_placeholders      = conn->ifc_settings->es_h3_placeholders;
    conn->ifc_peer_hq_settings.max_header_list_size  = HQ_DF_MAX_HEADER_LIST_SIZE;
    conn->ifc_peer_hq_settings.qpack_blocked_streams = HQ_DF_QPACK_BLOCKED_STREAMS;

    conn->ifc_conn.cn_if = ietf_full_conn_iface_ptr;
    conn->ifc_flags = flags | IFC_CREATED_OK;
    conn->ifc_max_ack_packno[PNS_INIT] = IQUIC_INVALID_PACKNO;
    conn->ifc_max_ack_packno[PNS_HSK] = IQUIC_INVALID_PACKNO;
    conn->ifc_max_ack_packno[PNS_APP] = IQUIC_INVALID_PACKNO;
    return 0;

  err1:
    lsquic_hash_destroy(conn->ifc_pub.all_streams);
  err0:
    return -1;
}


struct lsquic_conn *
lsquic_ietf_full_conn_client_new (struct lsquic_engine_public *enpub,
               const struct lsquic_stream_if *stream_if,
               void *stream_if_ctx,
               unsigned flags,
           const char *hostname, unsigned short max_packet_size, int is_ipv4,
           const unsigned char *zero_rtt, size_t zero_rtt_sz,
           const unsigned char *token, size_t token_sz)
{
    const struct enc_session_funcs_iquic *esfi;
    struct ietf_full_conn *conn;
    struct conn_cid_elem *cce;
    enum lsquic_version ver;
    unsigned versions;

    conn = calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;
    conn->ifc_conn.cn_cces = conn->ifc_cces;
    conn->ifc_conn.cn_n_cces = sizeof(conn->ifc_cces)
                                                / sizeof(conn->ifc_cces[0]);

    versions = enpub->enp_settings.es_versions & LSQUIC_IETF_VERSIONS;
    assert(versions);
    ver = highest_bit_set(versions);
    esfi = select_esf_iquic_by_ver(ver);
    cce = esfi->esfi_add_scid(enpub, &conn->ifc_conn);
    if (!cce)
    {
        free(conn);
        return NULL;
    }
    cce->cce_seqno = conn->ifc_scid_seqno++;
    cce->cce_flags = CCE_USED;

    if (!max_packet_size)
    {
        if (is_ipv4)
            max_packet_size = IQUIC_MAX_IPv4_PACKET_SZ;
        else
            max_packet_size = IQUIC_MAX_IPv6_PACKET_SZ;
    }
    conn->ifc_conn.cn_pack_size = max_packet_size;

    if (0 != ietf_full_conn_init(conn, enpub, stream_if, stream_if_ctx, flags))
    {
        free(conn);
        return NULL;
    }
    if (token)
    {
        if (0 != lsquic_send_ctl_set_token(&conn->ifc_send_ctl, token,
                                                                token_sz))
        {
            free(conn);
            return NULL;
        }
    }

    /* Do not infer anything about server limits before processing its
     * transport parameters.
     */
    conn->ifc_max_allowed_stream_id[SIT_BIDI_SERVER] =
        (enpub->enp_settings.es_max_streams_in << SIT_SHIFT) | SIT_BIDI_SERVER;
    conn->ifc_max_allowed_stream_id[SIT_UNI_SERVER] =
        (1 + (flags & IFC_HTTP ? 2 /* TODO push streams? */ : 0)) << SIT_SHIFT
                                                             | SIT_UNI_SERVER;

    init_ver_neg(conn, versions);
    assert(ver == conn->ifc_ver_neg.vn_ver);
    conn->ifc_conn.cn_pf = select_pf_by_ver(ver);
    conn->ifc_conn.cn_esf_c = select_esf_common_by_ver(ver);
    conn->ifc_conn.cn_esf.i = esfi;
    conn->ifc_conn.cn_enc_session =
    /* TODO: check retval */
            conn->ifc_conn.cn_esf.i->esfi_create_client(hostname,
                conn->ifc_enpub, &conn->ifc_conn, &conn->ifc_ver_neg,
                (void **) conn->ifc_crypto_streams, &crypto_stream_if);

    conn->ifc_crypto_streams[ENC_LEV_CLEAR] = lsquic_stream_new_crypto(
        ENC_LEV_CLEAR, &conn->ifc_pub, &lsquic_cry_sm_if,
        conn->ifc_conn.cn_enc_session,
        SCF_IETF|SCF_DI_AUTOSWITCH|SCF_CALL_ON_NEW|SCF_CRITICAL);
    if (!conn->ifc_crypto_streams[ENC_LEV_CLEAR])
    {
        /* TODO: free other stuff */
        free(conn);
        return NULL;
    }
    conn->ifc_pub.packet_out_malo =
                        lsquic_malo_create(sizeof(struct lsquic_packet_out));
    if (!conn->ifc_pub.packet_out_malo)
    {
        free(conn);
        lsquic_stream_destroy(conn->ifc_crypto_streams[ENC_LEV_CLEAR]);
        return NULL;
    }

    LSQ_DEBUG("negotiating version %s",
                            lsquic_ver2str[conn->ifc_ver_neg.vn_ver]);
    conn->ifc_process_incoming_packet = process_incoming_packet_verneg;
    LSQ_DEBUG("logging using %s SCID",
        LSQUIC_LOG_CONN_ID == CN_SCID(&conn->ifc_conn) ? "client" : "server");
    return &conn->ifc_conn;
}


static int
should_generate_ack (struct ietf_full_conn *conn)
{
    unsigned lost_acks;

    /* Need to set which ACKs are queued because generate_ack_frame() does not
     * generate ACKs unconditionally.
     */
    lost_acks = lsquic_send_ctl_lost_ack(&conn->ifc_send_ctl);
    if (lost_acks)
        conn->ifc_flags |= lost_acks << IFCBIT_ACK_QUED_SHIFT;

    return (conn->ifc_flags & IFC_ACK_QUEUED) != 0;
}


static int
ietf_full_conn_ci_can_write_ack (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    return should_generate_ack(conn);
}


static unsigned
ietf_full_conn_ci_cancel_pending_streams (struct lsquic_conn *lconn, unsigned n)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    if (n > conn->ifc_n_delayed_streams)
        conn->ifc_n_delayed_streams = 0;
    else
        conn->ifc_n_delayed_streams -= n;
    return conn->ifc_n_delayed_streams;
}


static int
generate_ack_frame_for_pns (struct ietf_full_conn *conn,
                struct lsquic_packet_out *packet_out, enum packnum_space pns)
{
    lsquic_time_t now;
    int has_missing, w;

    now = lsquic_time_now();
    w = conn->ifc_conn.cn_pf->pf_gen_ack_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out),
            (gaf_rechist_first_f)        lsquic_rechist_first,
            (gaf_rechist_next_f)         lsquic_rechist_next,
            (gaf_rechist_largest_recv_f) lsquic_rechist_largest_recv,
            &conn->ifc_rechist[pns], now, &has_missing, &packet_out->po_ack2ed,
            conn->ifc_incoming_ecn ? conn->ifc_ecn_counts_in[pns] : NULL);
    if (w < 0) {
        ABORT_ERROR("generating ACK frame failed: %d", errno);
        return -1;
    }
    char buf[0x100];
    lsquic_hexstr(packet_out->po_data + packet_out->po_data_sz, w, buf, sizeof(buf));
    LSQ_DEBUG("ACK bytes: %s", buf);
    EV_LOG_GENERATED_ACK_FRAME(LSQUIC_LOG_CONN_ID, conn->ifc_conn.cn_pf,
                        packet_out->po_data + packet_out->po_data_sz, w);
    lsquic_send_ctl_scheduled_ack(&conn->ifc_send_ctl, pns);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_ACK;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_regen_sz += w;
    if (has_missing)
        conn->ifc_flags |= IFC_ACK_HAD_MISS;
    else
        conn->ifc_flags &= ~IFC_ACK_HAD_MISS;
    LSQ_DEBUG("Put %d bytes of ACK frame into packet on outgoing queue", w);
    if (conn->ifc_n_cons_unretx >= 20 &&
                !lsquic_send_ctl_have_outgoing_retx_frames(&conn->ifc_send_ctl))
    {
        LSQ_DEBUG("schedule MAX_DATA frame after %u non-retx "
                                    "packets sent", conn->ifc_n_cons_unretx);
        conn->ifc_send_flags |= SF_SEND_MAX_DATA;
    }

    conn->ifc_n_slack_akbl[pns] = 0;
    lsquic_send_ctl_n_stop_waiting_reset(&conn->ifc_send_ctl, pns);
    conn->ifc_flags &= ~(IFC_ACK_QUED_INIT << pns);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_INIT + pns);
    lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
    LSQ_DEBUG("%s ACK state reset", lsquic_pns2str[pns]);

    return 0;
}


static void
generate_ack_frame (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    enum packnum_space pns;
    int s;

    for (pns = 0; pns < N_PNS; ++pns)
        if (conn->ifc_flags & (IFC_ACK_QUED_INIT << pns))
        {
            packet_out = lsquic_send_ctl_new_packet_out(&conn->ifc_send_ctl,
                                                                        0, pns);
            if (!packet_out)
            {
                ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
                return;
            }
            s = generate_ack_frame_for_pns(conn, packet_out, pns);
            lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
            if (s != 0)
                return;
        }
}


static struct lsquic_packet_out *
get_writeable_packet (struct ietf_full_conn *conn, unsigned need_at_least)
{
    struct lsquic_packet_out *packet_out;
    int is_err;

    packet_out = lsquic_send_ctl_get_writeable_packet(&conn->ifc_send_ctl,
                                            PNS_APP, need_at_least, &is_err);
    if (!packet_out && is_err)
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
    return packet_out;
}


static void
generate_max_data_frame (struct ietf_full_conn *conn)
{
    const uint64_t offset = lsquic_cfcw_get_fc_recv_off(&conn->ifc_pub.cfcw);
    struct lsquic_packet_out *packet_out;
    unsigned need;
    int w;

    need = conn->ifc_conn.cn_pf->pf_max_data_frame_size(offset);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return;
    w = conn->ifc_conn.cn_pf->pf_gen_max_data_frame(
                         packet_out->po_data + packet_out->po_data_sz,
                         lsquic_packet_out_avail(packet_out), offset);
    if (w < 0)
    {
        ABORT_ERROR("Generating MAX_DATA frame failed");
        return;
    }
    LSQ_DEBUG("generated %d-byte MAX_DATA frame (offset: %"PRIu64")", w, offset);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated MAX_DATA frame, offset=%"
                                                                PRIu64, offset);
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);
    packet_out->po_frame_types |= QUIC_FTBIT_MAX_DATA;
    conn->ifc_send_flags &= ~SF_SEND_MAX_DATA;
}


static int
generate_new_cid_frame (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    struct conn_cid_elem *cce;
    size_t need;
    int w;
    unsigned char token_buf[IQUIC_SRESET_TOKEN_SZ];

    assert(conn->ifc_enpub->enp_settings.es_scid_len);

    need = conn->ifc_conn.cn_pf->pf_new_connection_id_frame_size(
            conn->ifc_scid_seqno, conn->ifc_enpub->enp_settings.es_scid_len);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return -1;

    cce = conn->ifc_conn.cn_esf.i->esfi_add_scid(conn->ifc_enpub,
                                                            &conn->ifc_conn);
    if (!cce)
    {
        ABORT_WARN("cannot add a new SCID");
        return -1;
    }
    cce->cce_seqno = conn->ifc_scid_seqno++;

        memset(token_buf, 0, sizeof(token_buf));

    if (0 != lsquic_engine_add_cid(conn->ifc_enpub, &conn->ifc_conn,
                                                        cce - conn->ifc_cces))
    {
        ABORT_WARN("cannot track new SCID");
        return -1;
    }

    w = conn->ifc_conn.cn_pf->pf_gen_new_connection_id_frame(
            packet_out->po_data + packet_out->po_data_sz,
            lsquic_packet_out_avail(packet_out), cce->cce_seqno,
            &cce->cce_cid, token_buf, sizeof(token_buf));
    if (w < 0)
    {
        ABORT_ERROR("generating NEW_CONNECTION_ID frame failed: %d", errno);
        return -1;
    }
    LSQ_DEBUGC("generated %d-byte NEW_CONNECTION_ID frame (CID: %"CID_FMT")",
        w, CID_BITS(&cce->cce_cid));
    EV_LOG_GENERATED_NEW_CONNECTION_ID_FRAME(LSQUIC_LOG_CONN_ID,
        conn->ifc_conn.cn_pf, packet_out->po_data + packet_out->po_data_sz, w);
    packet_out->po_frame_types |= QUIC_FTBIT_NEW_CONNECTION_ID;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    if ((1 << conn->ifc_conn.cn_n_cces) - 1 == conn->ifc_conn.cn_cces_mask)
    {
        conn->ifc_send_flags &= ~SF_SEND_NEW_CID;
        LSQ_DEBUG("All %u SCID slots have been assigned",
                                                conn->ifc_conn.cn_n_cces);
    }

    return 0;
}


static void
generate_new_cid_frames (struct ietf_full_conn *conn)
{
    int s;

    do
        s = generate_new_cid_frame(conn);
    while (0 == s && (conn->ifc_send_flags & SF_SEND_NEW_CID));
}


static int
generate_retire_cid_frame (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    struct dcid_elem *dce;
    size_t need;
    int w;

    dce = TAILQ_FIRST(&conn->ifc_to_retire);
    assert(dce);

    need = conn->ifc_conn.cn_pf->pf_retire_cid_frame_size(dce->de_seqno);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return -1;

    w = conn->ifc_conn.cn_pf->pf_gen_retire_cid_frame(
        packet_out->po_data + packet_out->po_data_sz,
        lsquic_packet_out_avail(packet_out), dce->de_seqno);
    if (w < 0)
    {
        ABORT_ERROR("generating RETIRE_CONNECTION_ID frame failed: %d", errno);
        return -1;
    }
    LSQ_DEBUG("generated %d-byte RETIRE_CONNECTION_ID frame (seqno: %u)",
        w, dce->de_seqno);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated RETIRE_CONNECTION_ID "
                                            "frame, seqno=%u", dce->de_seqno);
    packet_out->po_frame_types |= QUIC_FTBIT_RETIRE_CONNECTION_ID;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    TAILQ_REMOVE(&conn->ifc_to_retire, dce, de_next_to_ret);
    lsquic_malo_put(dce);

    if (TAILQ_EMPTY(&conn->ifc_to_retire))
        conn->ifc_send_flags &= ~SF_SEND_RETIRE_CID;

    return 0;
}


static void
generate_retire_cid_frames (struct ietf_full_conn *conn)
{
    int s;

    do
        s = generate_retire_cid_frame(conn);
    while (0 == s && (conn->ifc_send_flags & SF_SEND_RETIRE_CID));
}


/* Return true if generated, false otherwise */
static int
generate_blocked_frame (struct ietf_full_conn *conn)
{
    const uint64_t offset = conn->ifc_pub.conn_cap.cc_blocked;
    struct lsquic_packet_out *packet_out;
    size_t need;
    int w;

    need = conn->ifc_conn.cn_pf->pf_blocked_frame_size(offset);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return 0;

    w = conn->ifc_conn.cn_pf->pf_gen_blocked_frame(
        packet_out->po_data + packet_out->po_data_sz,
        lsquic_packet_out_avail(packet_out), offset);
    if (w < 0)
    {
        ABORT_ERROR("generating BLOCKED frame failed: %d", errno);
        return 0;
    }
    LSQ_DEBUG("generated %d-byte BLOCKED frame (offset: %"PRIu64")", w, offset);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "generated BLOCKED frame, offset=%"
                                                                PRIu64, offset);
    packet_out->po_frame_types |= QUIC_FTBIT_BLOCKED;
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, w);

    return 1;
}


/* Return true if generated, false otherwise */
static int
generate_max_stream_data_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    struct lsquic_packet_out *packet_out;
    unsigned need;
    uint64_t off;
    int sz;

    off = lsquic_stream_fc_recv_off_const(stream);
    need = conn->ifc_conn.cn_pf->pf_max_stream_data_frame_size(stream->id, off);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return 0;
    sz = conn->ifc_conn.cn_pf->pf_gen_max_stream_data_frame(
                         packet_out->po_data + packet_out->po_data_sz,
                         lsquic_packet_out_avail(packet_out), stream->id, off);
    if (sz < 0)
    {
        ABORT_ERROR("Generating MAX_STREAM_DATA frame failed");
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_MAX_STREAM_DATA;
    lsquic_stream_max_stream_data_sent(stream);
    return 0;
}


/* Return true if generated, false otherwise */
static int
generate_stream_blocked_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    struct lsquic_packet_out *packet_out;
    unsigned need;
    uint64_t off;
    int sz;

    off = lsquic_stream_combined_send_off(stream);
    need = conn->ifc_conn.cn_pf->pf_stream_blocked_frame_size(stream->id, off);
    packet_out = get_writeable_packet(conn, need);
    if (!packet_out)
        return 0;
    sz = conn->ifc_conn.cn_pf->pf_gen_stream_blocked_frame(
                         packet_out->po_data + packet_out->po_data_sz,
                         lsquic_packet_out_avail(packet_out), stream->id, off);
    if (sz < 0)
    {
        ABORT_ERROR("Generating STREAM_BLOCKED frame failed");
        return 0;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_STREAM_BLOCKED;
    lsquic_stream_blocked_frame_sent(stream);
    return 0;
}


/* Return true if generated, false otherwise */
static int
generate_rst_stream_frame (struct ietf_full_conn *conn,
                                                struct lsquic_stream *stream)
{
    LSQ_WARN("%s: TODO", __func__);   /* TODO */
    return 0;
}


static int
is_our_stream (const struct ietf_full_conn *conn,
                                        const struct lsquic_stream *stream)
{
    return 0 == (1 & stream->id);
}


static int
is_peer_initiated (const struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    return 1 & stream_id;
}


#if 0
/* XXX seems we don't need this? */
static unsigned
count_streams (const struct ietf_full_conn *conn, enum stream_id_type sit)
{
    const struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    unsigned count;
    int peer;

    peer = is_peer_initiated(conn, sit);
    for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        count += (stream->id & SIT_MASK) == sit
              && !lsquic_stream_is_closed(stream)
                 /* When counting peer-initiated streams, do not include those
                  * that have been reset:
                  */
              && !(peer && lsquic_stream_is_reset(stream));
    }

    return count;
}


#endif


static void
conn_mark_stream_closed (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{   /* Because stream IDs are distributed unevenly, it is more efficient to
     * maintain four sets of closed stream IDs.
     */
    const enum stream_id_type idx = stream_id & SIT_MASK;
    stream_id >>= SIT_SHIFT;
    if (0 == lsquic_set64_add(&conn->ifc_closed_stream_ids[idx], stream_id))
        LSQ_DEBUG("marked stream %"PRIu64" as closed", stream_id);
    else
        ABORT_ERROR("could not add element to set: %s", strerror(errno));
}


static int
conn_is_stream_closed (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    enum stream_id_type idx = stream_id & SIT_MASK;
    stream_id >>= SIT_SHIFT;
    return lsquic_set64_has(&conn->ifc_closed_stream_ids[idx], stream_id);
}


static int
either_side_going_away (const struct ietf_full_conn *conn)
{
    return (conn->ifc_flags & IFC_GOING_AWAY)
        || (conn->ifc_conn.cn_flags & LSCONN_PEER_GOING_AWAY);
}


static void
maybe_create_delayed_streams (struct ietf_full_conn *conn)
{
    unsigned avail, delayed;

    delayed = conn->ifc_n_delayed_streams;
    if (0 == delayed)
        return;

    avail = ietf_full_conn_ci_n_avail_streams(&conn->ifc_conn);
    while (avail > 0)
    {
        if (0 == create_bidi_stream_out(conn))
        {
            --avail;
            --conn->ifc_n_delayed_streams;
            if (0 == conn->ifc_n_delayed_streams)
                break;
        }
        else
        {
            LSQ_INFO("cannot create BIDI stream");
            break;
        }
    }

    LSQ_DEBUG("created %u delayed stream%.*s",
        delayed - conn->ifc_n_delayed_streams,
        delayed - conn->ifc_n_delayed_streams != 1, "s");
}


static void
service_streams (struct ietf_full_conn *conn)
{
    struct lsquic_hash_elem *el;
    lsquic_stream_t *stream, *next;
    unsigned n_our_destroyed = 0;

    for (stream = TAILQ_FIRST(&conn->ifc_pub.service_streams); stream;
                                                                stream = next)
    {
        next = TAILQ_NEXT(stream, next_service_stream);
        if (stream->sm_qflags & SMQF_ABORT_CONN)
            /* No need to unset this flag or remove this stream: the connection
             * is about to be aborted.
             */
            ABORT_ERROR("aborted due to error in stream %"PRIu64, stream->id);
        if (stream->sm_qflags & SMQF_CALL_ONCLOSE)
            lsquic_stream_call_on_close(stream);
        if (stream->sm_qflags & SMQF_FREE_STREAM)
        {
            n_our_destroyed += is_our_stream(conn, stream);
            TAILQ_REMOVE(&conn->ifc_pub.service_streams, stream, next_service_stream);
            el = lsquic_hash_find(conn->ifc_pub.all_streams, &stream->id, sizeof(stream->id));
            if (el)
                lsquic_hash_erase(conn->ifc_pub.all_streams, el);
            conn_mark_stream_closed(conn, stream->id);
            lsquic_stream_destroy(stream);
        }
    }

    /* TODO: this chunk of code, too, should probably live elsewhere */
    if (either_side_going_away(conn))
        while (conn->ifc_n_delayed_streams)
        {
            --conn->ifc_n_delayed_streams;
            LSQ_DEBUG("goaway mode: delayed stream results in null ctor");
            (void) conn->ifc_stream_if->on_new_stream(conn->ifc_stream_ctx,
                                                                        NULL);
        }
    else if ((conn->ifc_flags & (IFC_HTTP|IFC_HAVE_PEER_SET)) != IFC_HTTP)
        maybe_create_delayed_streams(conn);
}


/* Return true if packetized, false otherwise */
static int
packetize_standalone_stream_reset (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    /* TODO */
    return 0;
}


static void
packetize_standalone_stream_resets (struct ietf_full_conn *conn)
{
    struct stream_id_to_reset *sitr;

    while ((sitr = STAILQ_FIRST(&conn->ifc_stream_ids_to_reset)))
        if (packetize_standalone_stream_reset(conn, sitr->sitr_stream_id))
        {
            STAILQ_REMOVE_HEAD(&conn->ifc_stream_ids_to_reset, sitr_next);
            free(sitr);
        }
        else
            break;
}


static int
process_stream_ready_to_send (struct ietf_full_conn *conn,
                                            struct lsquic_stream *stream)
{
    int r = 1;
    if (stream->sm_qflags & SMQF_SEND_MAX_STREAM_DATA)
        r &= generate_max_stream_data_frame(conn, stream);
    if (stream->sm_qflags & SMQF_SEND_BLOCKED)
        r &= generate_stream_blocked_frame(conn, stream);
    if (stream->sm_qflags & SMQF_SEND_RST)
        r &= generate_rst_stream_frame(conn, stream);
    return r;
}


static void
process_streams_ready_to_send (struct ietf_full_conn *conn)
{
    lsquic_stream_t *stream;

    assert(!TAILQ_EMPTY(&conn->ifc_pub.sending_streams));

    lsquic_prio_tree_iter_reset(conn->ifc_pub.u.ietf.prio_tree, "send");
    TAILQ_FOREACH(stream, &conn->ifc_pub.sending_streams, next_send_stream)
        lsquic_prio_tree_iter_add(conn->ifc_pub.u.ietf.prio_tree, stream);

    while ((stream = lsquic_prio_tree_iter_next(
                                        conn->ifc_pub.u.ietf.prio_tree)))
        if (!process_stream_ready_to_send(conn, stream))
            break;
}


static void
ietf_full_conn_ci_write_ack (struct lsquic_conn *lconn,
                                        struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    (void) generate_ack_frame_for_pns(conn, packet_out, PNS_APP);
}


static void
ietf_full_conn_ci_client_call_on_new (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    assert(conn->ifc_flags & IFC_CREATED_OK);
    conn->ifc_conn_ctx = conn->ifc_stream_if->on_new_conn(conn->ifc_stream_ctx,
                                                                        lconn);
}


static void
ietf_full_conn_ci_close (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    enum stream_dir sd;

    if (!(conn->ifc_flags & IFC_CLOSING))
    {
        for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
        {
            stream = lsquic_hashelem_getdata(el);
            sd = (stream->id >> SD_SHIFT) & 1;
            if (SD_BIDI == sd)
                lsquic_stream_shutdown_internal(stream);
        }
        conn->ifc_flags |= IFC_CLOSING;
        conn->ifc_send_flags |= SF_SEND_CONN_CLOSE;
    }
}


static void
ietf_full_conn_ci_destroy (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    struct dcid_elem **el, *dce;
    for (el = conn->ifc_dces; el < conn->ifc_dces + sizeof(conn->ifc_dces)
                                            / sizeof(conn->ifc_dces[0]); ++el)
        if (*el)
        {
            if ((*el)->de_hash_el.qhe_flags & QHE_HASHED)
                lsquic_hash_erase(conn->ifc_enpub->enp_srst_hash,
                                                        &(*el)->de_hash_el);
            lsquic_malo_put(*el);
        }
    while ((dce = TAILQ_FIRST(&conn->ifc_to_retire)))
    {
        TAILQ_REMOVE(&conn->ifc_to_retire, dce, de_next_to_ret);
        lsquic_malo_put(dce);
    }
    if (conn->ifc_flags & IFC_CREATED_OK)
        conn->ifc_stream_if->on_conn_closed(&conn->ifc_conn);
    if (conn->ifc_pub.u.ietf.prio_tree)
        lsquic_prio_tree_destroy(conn->ifc_pub.u.ietf.prio_tree);
    if (conn->ifc_conn.cn_enc_session)
        conn->ifc_conn.cn_esf.i->esfi_destroy(conn->ifc_conn.cn_enc_session);
    free(conn->ifc_errmsg);
    free(conn);
}


static void
ietf_full_conn_ci_going_away (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

        LSQ_NOTICE("going away has no effect in IETF QUIC");
}


static void
handshake_failed (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    LSQ_DEBUG("handshake failed");
    lsquic_alarmset_unset(&conn->ifc_alset, AL_HANDSHAKE);
    conn->ifc_flags |= IFC_HSK_FAILED;
    if (conn->ifc_stream_if->on_hsk_done)
        conn->ifc_stream_if->on_hsk_done(lconn, 0);
}


static struct dcid_elem *
get_new_dce (struct ietf_full_conn *conn)
{
    struct dcid_elem **el;

    for (el = conn->ifc_dces; el < conn->ifc_dces + sizeof(conn->ifc_dces)
                                            / sizeof(conn->ifc_dces[0]); ++el)
        if (!*el)
            return *el = lsquic_malo_get(conn->ifc_pub.mm->malo.dcid_elem);

    return NULL;
}


static void
handshake_ok (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    struct lsquic_stream *stream;
    struct lsquic_hash_elem *el;
    struct dcid_elem *dce;
    struct transport_params params;
    enum stream_id_type sit;
    uint32_t limit;
    char buf[0x200];

    /* Need to set this flag even we hit an error in the rest of this funciton.
     * This is because this flag is used to calculate packet out header size
     */
    lconn->cn_flags |= LSCONN_HANDSHAKE_DONE;

    if (0 != lconn->cn_esf.i->esfi_get_peer_transport_params(
                                            lconn->cn_enc_session, &params))
    {
        ABORT_WARN("could not get transport parameters");
        return;
    }

    LSQ_DEBUG("peer transport parameters: %s",
                        (lsquic_tp_to_str(&params, buf, sizeof(buf)), buf));

    sit = gen_sit(conn->ifc_flags & IFC_SERVER, SD_BIDI);
    conn->ifc_max_allowed_stream_id[sit] =
                        (params.tp_init_max_streams_bidi << SIT_SHIFT) | sit;
    sit = gen_sit(conn->ifc_flags & IFC_SERVER, SD_UNI);
    conn->ifc_max_allowed_stream_id[sit] =
                        (params.tp_init_max_streams_uni << SIT_SHIFT) | sit;

    conn->ifc_max_stream_data_uni      = params.tp_init_max_stream_data_uni;

    if (params.tp_init_max_data < conn->ifc_pub.conn_cap.cc_sent)
    {
        ABORT_WARN("peer specified init_max_data=%"PRIu64" bytes, which is "
            "smaller than the amount of data already sent on this connection "
            "(%"PRIu64" bytes)", params.tp_init_max_data,
            conn->ifc_pub.conn_cap.cc_sent);
        return;
    }

    conn->ifc_pub.conn_cap.cc_max = params.tp_init_max_data;

    for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
    {
        stream = lsquic_hashelem_getdata(el);
        if (is_our_stream(conn, stream))
            limit = params.tp_init_max_stream_data_bidi_remote;
        else
            limit = params.tp_init_max_stream_data_bidi_local;
        if (0 != lsquic_stream_set_max_send_off(stream, limit))
        {
            ABORT_WARN("cannot set peer-supplied max_stream_data=%"PRIu32
                "on stream %"PRIu64, limit, stream->id);
            return;
        }
    }

    conn->ifc_cfg.max_stream_send = params.tp_init_max_stream_data_bidi_remote;
    conn->ifc_cfg.ack_exp = params.tp_ack_delay_exponent;

    /* TODO: idle timeout, packet size */

    dce = get_new_dce(conn);
    if (!dce)
    {
        ABORT_WARN("cannot allocate DCE");
        return;
    }

    memset(dce, 0, sizeof(*dce));
    dce->de_cid = conn->ifc_conn.cn_dcid;
    dce->de_seqno = 0;
    if (params.tp_flags & TPI_STATELESS_RESET_TOKEN)
    {
        memcpy(dce->de_srst, params.tp_stateless_reset_token,
                                                    sizeof(dce->de_srst));
        dce->de_flags = DE_SRST;
        if (conn->ifc_enpub->enp_srst_hash)
        {
            if (!lsquic_hash_insert(conn->ifc_enpub->enp_srst_hash,
                    dce->de_srst, sizeof(dce->de_srst), &conn->ifc_conn,
                    &dce->de_hash_el))
            {
                ABORT_WARN("cannot insert DCE");
                return;
            }
        }
    }
    else
        dce->de_flags = 0;

    LSQ_INFO("applied peer transport parameters");

    if (conn->ifc_flags & IFC_HTTP)
    {
        lsquic_qeh_init(&conn->ifc_qeh, &conn->ifc_conn);
        if (0 == avail_streams_count(conn, conn->ifc_flags & IFC_SERVER,
                                                                    SD_UNI))
        {
            ABORT_WARN("cannot create control stream due to peer-imposed "
                                                                    "limit");
            conn->ifc_error = CONN_ERR(1, HEC_GENERAL_PROTOCOL_ERROR);
            return;
        }
        if (0 != create_ctl_stream_out(conn))
        {
            ABORT_WARN("cannot create outgoing control stream");
            return;
        }
        if (0 != lsquic_hcso_write_settings(&conn->ifc_hcso,
                &conn->ifc_enpub->enp_settings, conn->ifc_flags & IFC_SERVER))
        {
            ABORT_WARN("cannot write SETTINGS");
            return;
        }
        if (0 != lsquic_qdh_init(&conn->ifc_qdh, &conn->ifc_conn,
                                conn->ifc_flags & IFC_SERVER, conn->ifc_enpub,
                                conn->ifc_settings->es_qpack_dec_max_size,
                                conn->ifc_settings->es_qpack_dec_max_blocked))
        {
            ABORT_WARN("cannot initialize QPACK decoder");
            return;
        }
        if (avail_streams_count(conn, conn->ifc_flags & IFC_SERVER, SD_UNI) > 0)
        {
            if (0 != create_qdec_stream_out(conn))
            {
                ABORT_WARN("cannot create outgoing QPACK decoder stream");
                return;
            }
        }
        else
            LSQ_DEBUG("cannot create outgoing QPACK decoder stream due to "
                "unidir limits");
    }

    if ((1 << conn->ifc_conn.cn_n_cces) - 1 != conn->ifc_conn.cn_cces_mask
            && CN_SCID(&conn->ifc_conn)->len != 0)
        conn->ifc_send_flags |= SF_SEND_NEW_CID;
    if ((conn->ifc_flags & (IFC_HTTP|IFC_HAVE_PEER_SET)) != IFC_HTTP)
        maybe_create_delayed_streams(conn);
}


static void
ietf_full_conn_ci_hsk_done (struct lsquic_conn *lconn,
                                                enum lsquic_hsk_status status)
{
    switch (status)
    {
    case LSQ_HSK_OK:
    case LSQ_HSK_0RTT_OK:
        handshake_ok(lconn);
        break;
    default:
        assert(0);
        /* fall-through */
    case LSQ_HSK_FAIL:
        handshake_failed(lconn);
        break;
    }
}


static int
ietf_full_conn_ci_is_push_enabled (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;

    LSQ_DEBUG("%s: not yet (TODO)", __func__);
    return 0;
}


static int
ietf_full_conn_ci_is_tickable (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    struct lsquic_stream *stream;

    if (!TAILQ_EMPTY(&conn->ifc_pub.service_streams))
    {
        LSQ_DEBUG("tickable: there are streams to be serviced");
        return 1;
    }

    if (lsquic_send_ctl_can_send(&conn->ifc_send_ctl)
        && (should_generate_ack(conn) ||
            !lsquic_send_ctl_sched_is_blocked(&conn->ifc_send_ctl)))
    {
        /* XXX What about queued ACKs: why check but not make tickable? */
        if (conn->ifc_send_flags)
        {
            LSQ_DEBUG("tickable: send flags: 0x%X", conn->ifc_send_flags);
            return 1;
        }
        if (lsquic_send_ctl_has_buffered(&conn->ifc_send_ctl))
        {
            LSQ_DEBUG("tickable: has buffered packets");
            return 1;
        }
        if (!TAILQ_EMPTY(&conn->ifc_pub.sending_streams))
        {
            LSQ_DEBUG("tickable: there are sending streams");
            return 1;
        }
        TAILQ_FOREACH(stream, &conn->ifc_pub.write_streams, next_write_stream)
            if (lsquic_stream_write_avail(stream))
            {
                LSQ_DEBUG("tickable: stream %"PRIu64" can be written to",
                    stream->id);
                return 1;
            }
    }

    TAILQ_FOREACH(stream, &conn->ifc_pub.read_streams, next_read_stream)
        if (lsquic_stream_readable(stream))
        {
            LSQ_DEBUG("tickable: stream %"PRIu64" can be read from",
                stream->id);
            return 1;
        }

    LSQ_DEBUG("not tickable");
    return 0;
}


static enum tick_st
immediate_close (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    const char *error_reason;
    struct conn_err conn_err;
    int sz;

    if (conn->ifc_flags & (IFC_TICK_CLOSE|IFC_GOT_PRST))
        return TICK_CLOSE;

    conn->ifc_flags |= IFC_TICK_CLOSE;

    /* No reason to send anything that's been scheduled if connection is
     * being closed immedately.  This also ensures that packet numbers
     * sequence is always increasing.
     */
    lsquic_send_ctl_drop_scheduled(&conn->ifc_send_ctl);

    if ((conn->ifc_flags & IFC_TIMED_OUT)
                                    && conn->ifc_settings->es_silent_close)
        return TICK_CLOSE;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->ifc_send_ctl, 0,
                                                                    PNS_APP);
    if (!packet_out)
    {
        LSQ_WARN("cannot allocate packet: %s", strerror(errno));
        return TICK_CLOSE;
    }

    assert(conn->ifc_flags & (IFC_ERROR|IFC_ABORTED|IFC_TIMED_OUT|IFC_HSK_FAILED));
    if (conn->ifc_error.u.err != 0)
    {
        conn_err = conn->ifc_error;
        error_reason = conn->ifc_errmsg;
    }
    else if (conn->ifc_flags & IFC_ERROR)
    {
        conn_err = CONN_ERR(0, TEC_INTERNAL_ERROR);
        error_reason = "connection error";
    }
    else if (conn->ifc_flags & IFC_ABORTED)
    {
        conn_err = CONN_ERR(0, TEC_NO_ERROR);
        error_reason = "user aborted connection";
    }
    else if (conn->ifc_flags & IFC_TIMED_OUT)
    {
        conn_err = CONN_ERR(0, TEC_NO_ERROR);
        error_reason = "connection timed out";
    }
    else if (conn->ifc_flags & IFC_HSK_FAILED)
    {
        conn_err = CONN_ERR(0, TEC_NO_ERROR);
        error_reason = "handshake failed";
    }
    else
    {
        conn_err = CONN_ERR(0, TEC_NO_ERROR);
        error_reason = NULL;
    }

    lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
    sz = conn->ifc_conn.cn_pf->pf_gen_connect_close_frame(
                     packet_out->po_data + packet_out->po_data_sz,
                     lsquic_packet_out_avail(packet_out), conn_err.app_error,
                     conn_err.u.err, error_reason,
                     error_reason ? strlen(error_reason) : 0);
    if (sz < 0) {
        LSQ_WARN("%s failed", __func__);
        return TICK_CLOSE;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CONNECTION_CLOSE;
    LSQ_DEBUG("generated CONNECTION_CLOSE frame in its own packet");
    return TICK_SEND|TICK_CLOSE;
}


static void
process_streams_read_events (struct ietf_full_conn *conn)
{
    struct lsquic_stream *stream;
    int have_streams, iters;
    enum stream_q_flags q_flags, needs_service;
    static const char *const labels[2] = { "read-0", "read-1", };

    conn->ifc_pub.cp_flags &= ~CP_STREAM_UNBLOCKED;
    iters = 0;
    do
    {
        have_streams = 0;
        TAILQ_FOREACH(stream, &conn->ifc_pub.read_streams, next_read_stream)
            if (lsquic_stream_readable(stream))
            {
                if (!have_streams)
                {
                    ++have_streams;
                    lsquic_prio_tree_iter_reset(conn->ifc_pub.u.ietf.prio_tree,
                                                                labels[iters]);
                }
                lsquic_prio_tree_iter_add(conn->ifc_pub.u.ietf.prio_tree,
                                                                    stream);
            }

        if (!have_streams)
            break;

        needs_service = 0;
        while ((stream = lsquic_prio_tree_iter_next(
                                        conn->ifc_pub.u.ietf.prio_tree)))
        {
            q_flags = stream->sm_qflags & SMQF_SERVICE_FLAGS;
            lsquic_stream_dispatch_read_events(stream);
            needs_service |= q_flags ^ (stream->sm_qflags & SMQF_SERVICE_FLAGS);
        }
        if (needs_service)
            service_streams(conn);
    }
    while (iters++ == 0 && (conn->ifc_pub.cp_flags & CP_STREAM_UNBLOCKED));
}


static void
process_crypto_stream_read_events (struct ietf_full_conn *conn)
{
    struct lsquic_stream **stream;

    for (stream = conn->ifc_crypto_streams; stream <
            conn->ifc_crypto_streams + sizeof(conn->ifc_crypto_streams)
                    / sizeof(conn->ifc_crypto_streams[0]); ++stream)
        if (*stream && (*stream)->sm_qflags & SMQF_WANT_READ)
            lsquic_stream_dispatch_read_events(*stream);
}


static void
process_crypto_stream_write_events (struct ietf_full_conn *conn)
{
    struct lsquic_stream **stream;

    for (stream = conn->ifc_crypto_streams; stream <
            conn->ifc_crypto_streams + sizeof(conn->ifc_crypto_streams)
                    / sizeof(conn->ifc_crypto_streams[0]); ++stream)
        if (*stream && (*stream)->sm_qflags & SMQF_WANT_WRITE)
            lsquic_stream_dispatch_write_events(*stream);
}


static void
maybe_conn_flush_special_streams (struct ietf_full_conn *conn)
{
    if (!(conn->ifc_flags & IFC_HTTP))
        return;

    struct lsquic_stream *const streams[] = {
        conn->ifc_hcso.how_stream,
        conn->ifc_qeh.qeh_enc_sm_out,
        conn->ifc_qdh.qdh_dec_sm_out,
    };
    struct lsquic_stream *const *stream;

    for (stream = streams; stream < streams + sizeof(streams)
                                            / sizeof(streams[0]); ++stream)
        if (*stream && lsquic_stream_has_data_to_flush(*stream))
            (void) lsquic_stream_flush(*stream);
}


static int
write_is_possible (struct ietf_full_conn *conn)
{
    const lsquic_packet_out_t *packet_out;

    packet_out = lsquic_send_ctl_last_scheduled(&conn->ifc_send_ctl, PNS_APP);
    return (packet_out && lsquic_packet_out_avail(packet_out) > 10)
        || lsquic_send_ctl_can_send(&conn->ifc_send_ctl);
}


/* Write events are dispatched in two steps.  First, only the high-priority
 * streams are processed.  High-priority streams are critical streams plus
 * one non-critical streams with the highest priority.  In the second step,
 * all other streams are processed.
 */
static void
process_streams_write_events (struct ietf_full_conn *conn, int high_prio,
                                const struct lsquic_stream **highest_non_crit)
{
    struct lsquic_stream *stream;
    struct h3_prio_tree *const prio_tree = conn->ifc_pub.u.ietf.prio_tree;

    if (high_prio)
        *highest_non_crit = lsquic_prio_tree_highest_non_crit(prio_tree);
    lsquic_prio_tree_iter_reset(prio_tree, high_prio ? "write-high" :
                                                                "write-low");
    TAILQ_FOREACH(stream, &conn->ifc_pub.write_streams, next_write_stream)
        if (high_prio ==
                (stream == *highest_non_crit ||
                                        lsquic_stream_is_critical(stream)))
            lsquic_prio_tree_iter_add(prio_tree, stream);


    while ((stream = lsquic_prio_tree_iter_next(
                                        conn->ifc_pub.u.ietf.prio_tree)))
        lsquic_stream_dispatch_write_events(stream);

    maybe_conn_flush_special_streams(conn);
}


static int
conn_ok_to_close (const struct ietf_full_conn *conn)
{
    assert(conn->ifc_flags & IFC_CLOSING);
    return 1;
}


static void
generate_connection_close_packet (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    int sz;

    packet_out = lsquic_send_ctl_new_packet_out(&conn->ifc_send_ctl, 0, PNS_APP);
    if (!packet_out)
    {
        ABORT_ERROR("cannot allocate packet: %s", strerror(errno));
        return;
    }

    lsquic_send_ctl_scheduled_one(&conn->ifc_send_ctl, packet_out);
    sz = conn->ifc_conn.cn_pf->pf_gen_connect_close_frame(
                packet_out->po_data + packet_out->po_data_sz,
                lsquic_packet_out_avail(packet_out), 0, TEC_NO_ERROR, NULL, 0);
    if (sz < 0) {
        ABORT_ERROR("generate_connection_close_packet failed");
        return;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_CONNECTION_CLOSE;
    LSQ_DEBUG("generated CONNECTION_CLOSE frame in its own packet");
    conn->ifc_send_flags &= ~SF_SEND_CONN_CLOSE;
}


static int
generate_ping_frame (struct ietf_full_conn *conn)
{
    struct lsquic_packet_out *packet_out;
    int sz;

    packet_out = get_writeable_packet(conn, 1);
    if (!packet_out)
    {
        LSQ_DEBUG("cannot get writeable packet for PING frame");
        return 1;
    }
    sz = conn->ifc_conn.cn_pf->pf_gen_ping_frame(
                            packet_out->po_data + packet_out->po_data_sz,
                            lsquic_packet_out_avail(packet_out));
    if (sz < 0) {
        ABORT_ERROR("gen_ping_frame failed");
        return 1;
    }
    lsquic_send_ctl_incr_pack_sz(&conn->ifc_send_ctl, packet_out, sz);
    packet_out->po_frame_types |= 1 << QUIC_FRAME_PING;
    LSQ_DEBUG("wrote PING frame");
    return 0;
}


static struct lsquic_packet_out *
ietf_full_conn_ci_next_packet_to_send (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    return lsquic_send_ctl_next_packet_to_send(&conn->ifc_send_ctl);
}


static lsquic_time_t
ietf_full_conn_ci_next_tick_time (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    lsquic_time_t alarm_time, pacer_time;

    alarm_time = lsquic_alarmset_mintime(&conn->ifc_alset);
    pacer_time = lsquic_send_ctl_next_pacer_time(&conn->ifc_send_ctl);

    if (alarm_time && pacer_time)
    {
        if (alarm_time < pacer_time)
            return alarm_time;
        else
            return pacer_time;
    }
    else if (alarm_time)
        return alarm_time;
    else
        return pacer_time;
}


static ptrdiff_t
count_zero_bytes (const unsigned char *p, size_t len)
{
    const unsigned char *const end = p + len;
    while (p < end && 0 == *p)
        ++p;
    return len - (end - p);
}


static unsigned
process_padding_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    return (unsigned) count_zero_bytes(p, len);
}


static int
process_ack (struct ietf_full_conn *conn, struct ack_info *acki,
             lsquic_time_t received)
{
    enum packnum_space pns;
    lsquic_packno_t packno;

    LSQ_DEBUG("Processing ACK");
    if (0 == lsquic_send_ctl_got_ack(&conn->ifc_send_ctl, acki, received))
    {
        pns = acki->pns;
        packno = lsquic_send_ctl_largest_ack2ed(&conn->ifc_send_ctl, pns);
        /* FIXME TODO zero is a valid packet number */
        if (packno)
            lsquic_rechist_stop_wait(&conn->ifc_rechist[ pns ], packno + 1);
        return 0;
    }
    else
    {
        ABORT_ERROR("Received invalid ACK");
        return -1;
    }
}


static int
process_saved_ack (struct ietf_full_conn *conn, int restore_parsed_ack)
{
    struct ack_info *const acki = conn->ifc_pub.mm->acki;
    struct lsquic_packno_range range;
    unsigned n_ranges, n_timestamps;
    lsquic_time_t lack_delta;
    int retval;

#ifdef WIN32
    /* Useless initialization to mollify MSVC: */
    memset(&range, 0, sizeof(range));
    n_ranges = 0;
    n_timestamps = 0;
    lack_delta = 0;
#endif

    if (restore_parsed_ack)
    {
        n_ranges     = acki->n_ranges;
        n_timestamps = acki->n_timestamps;
        lack_delta   = acki->lack_delta;
        range        = acki->ranges[0];
    }

    acki->pns          = PNS_APP;
    acki->n_ranges     = 1;
    acki->n_timestamps = conn->ifc_saved_ack_info.sai_n_timestamps;
    acki->lack_delta   = conn->ifc_saved_ack_info.sai_lack_delta;
    acki->ranges[0]    = conn->ifc_saved_ack_info.sai_range;

    retval = process_ack(conn, acki, conn->ifc_saved_ack_received);

    if (restore_parsed_ack)
    {
        acki->n_ranges     = n_ranges;
        acki->n_timestamps = n_timestamps;
        acki->lack_delta   = lack_delta;
        acki->ranges[0]    = range;
    }

    return retval;
}


static int
new_ack_is_superset (const struct short_ack_info *old, const struct ack_info *new)
{
    const struct lsquic_packno_range *new_range;

    new_range = &new->ranges[ new->n_ranges - 1 ];
    return new_range->low  <= old->sai_range.low
        && new_range->high >= old->sai_range.high;
}


static int
merge_saved_to_new (const struct short_ack_info *old, struct ack_info *new)
{
    struct lsquic_packno_range *smallest_range;

    assert(new->n_ranges > 1);
    smallest_range = &new->ranges[ new->n_ranges - 1 ];
    if (old->sai_range.high <= smallest_range->high
        && old->sai_range.high >= smallest_range->low
        && old->sai_range.low < smallest_range->low)
    {
        smallest_range->low = old->sai_range.low;
        return 1;
    }
    else
        return 0;
}


static int
merge_new_to_saved (struct short_ack_info *old, const struct ack_info *new)
{
    const struct lsquic_packno_range *new_range;

    assert(new->n_ranges == 1);
    new_range = &new->ranges[0];
    /* Only merge if new is higher, for simplicity.  This is also the
     * expected case.
     */
    if (new_range->high > old->sai_range.high
        && new_range->low > old->sai_range.low)
    {
        old->sai_range.high = new_range->high;
        return 1;
    }
    else
        return 0;
}


static unsigned
process_path_challenge_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    int parsed_len;
    char hexbuf[ sizeof(conn->ifc_path_chal) * 2 + 1 ];

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_path_chal_frame(p, len,
                                                        &conn->ifc_path_chal);
    if (parsed_len > 0)
    {
        LSQ_DEBUG("received path challenge: %s",
            HEXSTR((unsigned char *) &conn->ifc_path_chal,
            sizeof(conn->ifc_path_chal), hexbuf));
        conn->ifc_send_flags |= SF_SEND_PATH_RESP;
        return parsed_len;
    }
    else
        return 0;
}


static unsigned
process_path_response_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    int parsed_len;
    uint64_t path_resp;
    char hexbuf[ sizeof(conn->ifc_path_chal) * 2 + 1 ];

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_path_resp_frame(p, len,
                                                                &path_resp);
    if (parsed_len > 0)
    {
        LSQ_DEBUG("received path response: %s",
            HEXSTR((unsigned char *) &path_resp, sizeof(path_resp), hexbuf));
        /* TODO: do something here */
        return parsed_len;
    }
    else
        return 0;
}


static lsquic_stream_t *
find_stream_by_id (struct ietf_full_conn *conn, lsquic_stream_id_t stream_id)
{
    struct lsquic_hash_elem *el;
    el = lsquic_hash_find(conn->ifc_pub.all_streams, &stream_id,
                                                            sizeof(stream_id));
    if (el)
        return lsquic_hashelem_getdata(el);
    else
        return NULL;
}


static void
maybe_schedule_reset_for_stream (struct ietf_full_conn *conn,
                                                lsquic_stream_id_t stream_id)
{
    struct stream_id_to_reset *sitr;

    if (conn_is_stream_closed(conn, stream_id))
        return;

    sitr = malloc(sizeof(*sitr));
    if (!sitr)
        return;

    sitr->sitr_stream_id = stream_id;
    STAILQ_INSERT_TAIL(&conn->ifc_stream_ids_to_reset, sitr, sitr_next);
    conn_mark_stream_closed(conn, stream_id);
}


/* This function is called to create incoming streams */
static struct lsquic_stream *
new_stream (struct ietf_full_conn *conn, lsquic_stream_id_t stream_id,
            enum stream_ctor_flags flags)
{
    const struct lsquic_stream_if *iface;
    void *stream_ctx;
    struct lsquic_stream *stream;
    unsigned initial_window;
    const int call_on_new = flags & SCF_CALL_ON_NEW;

    flags &= ~SCF_CALL_ON_NEW;
    flags |= SCF_DI_AUTOSWITCH|SCF_IETF;

    if ((conn->ifc_flags & IFC_HTTP) && ((stream_id >> SD_SHIFT) & 1) == SD_UNI)
    {
        iface = unicla_if_ptr;
        stream_ctx = conn;
        /* FIXME: This logic does not work for push streams.  Perhaps one way
         * to address this is to reclassify them later?
         */
        flags |= SCF_CRITICAL;
    }
    else
    {
        iface = conn->ifc_stream_if;
        stream_ctx = conn->ifc_stream_ctx;
        if (conn->ifc_enpub->enp_settings.es_rw_once)
            flags |= SCF_DISP_RW_ONCE;
        if (conn->ifc_flags & IFC_HTTP)
            flags |= SCF_HTTP;
    }

    if (((stream_id >> SD_SHIFT) & 1) == SD_UNI)
        initial_window = conn->ifc_enpub->enp_settings
                                        .es_init_max_stream_data_uni;
    else
        initial_window = conn->ifc_enpub->enp_settings
                                        .es_init_max_stream_data_bidi_remote;

    stream = lsquic_stream_new(stream_id, &conn->ifc_pub,
                               iface, stream_ctx, initial_window,
                               conn->ifc_cfg.max_stream_send, flags);
    if (stream)
    {
        if (lsquic_hash_insert(conn->ifc_pub.all_streams, &stream->id,
                            sizeof(stream->id), stream, &stream->sm_hash_el))
        {
            if (call_on_new)
                lsquic_stream_call_on_new(stream);
        }
        else
        {
            lsquic_stream_destroy(stream);
            stream = NULL;
        }
    }
    return stream;
}


static unsigned
process_rst_stream_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    lsquic_stream_id_t stream_id;
    uint32_t error_code;
    uint64_t offset;
    lsquic_stream_t *stream;
    int call_on_new;
    const int parsed_len = conn->ifc_conn.cn_pf->pf_parse_rst_frame(p, len,
                                            &stream_id, &offset, &error_code);
    if (parsed_len < 0)
        return 0;

    EV_LOG_RST_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, offset,
                                                                error_code);
    LSQ_DEBUG("Got RST_STREAM; stream: %"PRIu64"; offset: 0x%"PRIX64, stream_id,
                                                                    offset);

    call_on_new = 0;
    stream = find_stream_by_id(conn, stream_id);
    if (!stream)
    {
        if (conn_is_stream_closed(conn, stream_id))
        {
            LSQ_DEBUG("got reset frame for closed stream %"PRIu64, stream_id);
            return parsed_len;
        }
        if (!is_peer_initiated(conn, stream_id))
        {
            ABORT_ERROR("received reset for never-initiated stream %"PRIu64,
                                                                    stream_id);
            return 0;
        }

        stream = new_stream(conn, stream_id, 0);
        if (!stream)
        {
            ABORT_ERROR("cannot create new stream: %s", strerror(errno));
            return 0;
        }
        ++call_on_new;
        if (stream_id > conn->ifc_max_peer_stream_id)
            conn->ifc_max_peer_stream_id = stream_id;
    }

    if (0 != lsquic_stream_rst_in(stream, offset, error_code))
    {
        ABORT_ERROR("received invalid RST_STREAM");
        return 0;
    }
    if (call_on_new)
        lsquic_stream_call_on_new(stream);
    return parsed_len;
}


static unsigned
process_stop_sending_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id, max_allowed;
    uint16_t error_code;
    int parsed_len, our_stream;
    enum stream_state_sending sss;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_stop_sending_frame(p, len,
                                                    &stream_id, &error_code);
    if (parsed_len < 0)
        return 0;

    EV_LOG_STOP_SENDING_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_id, error_code);
    LSQ_DEBUG("Got STOP_SENDING; stream: %"PRIu64"; error code: 0x%"PRIX16,
                                                        stream_id, error_code);

    our_stream = !is_peer_initiated(conn, stream_id);
    if (((stream_id >> SD_SHIFT) == SD_UNI) && !our_stream)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "received STOP_SENDING frame "
                                                "for receive-only stream");
        return 0;
    }

    stream = find_stream_by_id(conn, stream_id);
    if (stream)
    {
        if (our_stream &&
                    SSS_READY == (sss = lsquic_stream_sending_state(stream)))
        {
            ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "stream %"PRIu64" is in "
                "%s state: receipt of STOP_SENDING frame is a violation",
                stream_id, lsquic_sss2str[sss]);
            return 0;
        }
        lsquic_stream_stop_sending_in(stream, error_code);
    }
    else if (conn_is_stream_closed(conn, stream_id))
        LSQ_DEBUG("stream %"PRIu64" is closed: ignore STOP_SENDING frame",
            stream_id);
    else if (our_stream)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "received STOP_SENDING frame "
            "on locally initiated stream that has not yet been opened");
        return 0;
    }
    else
    {
        max_allowed = conn->ifc_max_allowed_stream_id[stream_id & SIT_MASK];
        if (stream_id > max_allowed)
        {
            ABORT_QUIETLY(0, TEC_STREAM_ID_ERROR, "incoming STOP_SENDING for "
                "stream %"PRIu64" would exceed allowed max of %"PRIu64,
                stream_id, max_allowed);
            return 0;
        }
        if (conn->ifc_flags & IFC_GOING_AWAY)
        {
            LSQ_DEBUG("going away: reset new incoming stream %"PRIu64,
                                                                    stream_id);
            maybe_schedule_reset_for_stream(conn, stream_id);
            return parsed_len;
        }
        stream = new_stream(conn, stream_id, 0);
        if (!stream)
        {
            ABORT_ERROR("cannot create new stream: %s", strerror(errno));
            return 0;
        }
        if (stream_id > conn->ifc_max_peer_stream_id)
            conn->ifc_max_peer_stream_id = stream_id;
        lsquic_stream_stop_sending_in(stream, error_code);
        lsquic_stream_call_on_new(stream);
    }

    return parsed_len;
}


static unsigned
process_crypto_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct stream_frame *stream_frame;
    struct lsquic_stream *stream;
    enum enc_level enc_level;
    int parsed_len;

    stream_frame = lsquic_malo_get(conn->ifc_pub.mm->malo.stream_frame);
    if (!stream_frame)
    {
        LSQ_WARN("could not allocate stream frame: %s", strerror(errno));
        return 0;
    }

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_crypto_frame(p, len,
                                                                stream_frame);
    if (parsed_len < 0) {
        lsquic_malo_put(stream_frame);
        return 0;
    }
    enc_level = lsquic_packet_in_enc_level(packet_in);
    EV_LOG_CRYPTO_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_frame, enc_level);
    LSQ_DEBUG("Got CRYPTO frame for enc level #%u", enc_level);

    if (conn->ifc_flags & IFC_CLOSING)
    {
        LSQ_DEBUG("Connection closing: ignore frame");
        lsquic_malo_put(stream_frame);
        return parsed_len;
    }

    if (conn->ifc_crypto_streams[enc_level])
        stream = conn->ifc_crypto_streams[enc_level];
    else
    {
        stream = lsquic_stream_new_crypto(enc_level, &conn->ifc_pub,
                    &lsquic_cry_sm_if, conn->ifc_conn.cn_enc_session,
                    SCF_IETF|SCF_DI_AUTOSWITCH|SCF_CALL_ON_NEW|SCF_CRITICAL);
        if (!stream)
        {
            lsquic_malo_put(stream_frame);
            ABORT_WARN("cannot create crypto stream for level %u", enc_level);
            return 0;
        }
        conn->ifc_crypto_streams[enc_level] = stream;
        (void) lsquic_stream_wantread(stream, 1);
    }

    stream_frame->packet_in = lsquic_packet_in_get(packet_in);
    if (0 != lsquic_stream_frame_in(stream, stream_frame))
    {
        ABORT_ERROR("cannot insert stream frame");
        return 0;
    }

    if (!(conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
    {   /* To enable decryption, process handshake stream as soon as its
         * data frames are received.
         *
         * TODO: this does not work when packets are reordered.  A more
         * flexible solution would defer packet decryption if handshake
         * has not been completed yet.  Nevertheless, this is good enough
         * for now.
         */
        lsquic_stream_dispatch_read_events(stream);
    }

    return parsed_len;
}


static unsigned
process_stream_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct stream_frame *stream_frame;
    struct lsquic_stream *stream;
    int parsed_len;

    stream_frame = lsquic_malo_get(conn->ifc_pub.mm->malo.stream_frame);
    if (!stream_frame)
    {
        LSQ_WARN("could not allocate stream frame: %s", strerror(errno));
        return 0;
    }

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_stream_frame(p, len,
                                                                stream_frame);
    if (parsed_len < 0) {
        lsquic_malo_put(stream_frame);
        return 0;
    }
    EV_LOG_STREAM_FRAME_IN(LSQUIC_LOG_CONN_ID, stream_frame);
    LSQ_DEBUG("Got stream frame for stream #%"PRIu64, stream_frame->stream_id);

    if (conn->ifc_flags & IFC_CLOSING)
    {
        LSQ_DEBUG("Connection closing: ignore frame");
        lsquic_malo_put(stream_frame);
        return parsed_len;
    }

    stream = find_stream_by_id(conn, stream_frame->stream_id);
    if (!stream)
    {
        if (conn_is_stream_closed(conn, stream_frame->stream_id))
        {
            LSQ_DEBUG("drop frame for closed stream %"PRIu64,
                                                stream_frame->stream_id);
            lsquic_malo_put(stream_frame);
            return parsed_len;
        }
        if (is_peer_initiated(conn, stream_frame->stream_id))
        {
            const lsquic_stream_id_t max_allowed =
                conn->ifc_max_allowed_stream_id[stream_frame->stream_id & SIT_MASK];
            if (stream_frame->stream_id > max_allowed)
            {
                ABORT_WARN("incoming stream %"PRIu64" exceeds allowed max of "
                    "%"PRIu64, stream_frame->stream_id, max_allowed);
                lsquic_malo_put(stream_frame);
                return 0;
            }
            if (conn->ifc_flags & IFC_GOING_AWAY)
            {
                LSQ_DEBUG("going away: reset new incoming stream %"PRIu64,
                                                    stream_frame->stream_id);
                maybe_schedule_reset_for_stream(conn, stream_frame->stream_id);
                lsquic_malo_put(stream_frame);
                return parsed_len;
            }
        }
        else
        {
            ABORT_QUIETLY(0, TEC_STREAM_STATE_ERROR, "received STREAM frame "
                                                "for never-initiated stream");
            lsquic_malo_put(stream_frame);
            return 0;
        }
        stream = new_stream(conn, stream_frame->stream_id, SCF_CALL_ON_NEW);
        if (!stream)
        {
            ABORT_ERROR("cannot create new stream: %s", strerror(errno));
            lsquic_malo_put(stream_frame);
            return 0;
        }
        if (stream_frame->stream_id > conn->ifc_max_peer_stream_id)
            conn->ifc_max_peer_stream_id = stream_frame->stream_id;
    }

    stream_frame->packet_in = lsquic_packet_in_get(packet_in);
    if (0 != lsquic_stream_frame_in(stream, stream_frame))
    {
        ABORT_ERROR("cannot insert stream frame");
        return 0;
    }

    return parsed_len;
}


static unsigned
process_ack_frame (struct ietf_full_conn *conn,
    struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct ack_info *const new_acki = conn->ifc_pub.mm->acki;
    enum packnum_space pns;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_ack_frame(p, len, new_acki,
                                                        conn->ifc_cfg.ack_exp);
    if (parsed_len < 0)
        goto err;

    pns = lsquic_hety2pns[ packet_in->pi_header_type ];
    if (is_valid_packno(conn->ifc_max_ack_packno[pns]) &&
                        packet_in->pi_packno <= conn->ifc_max_ack_packno[pns])
    {
        LSQ_DEBUG("Ignore old ack (max %"PRIu64")",
                                                conn->ifc_max_ack_packno[pns]);
        return parsed_len;
    }

    EV_LOG_ACK_FRAME_IN(LSQUIC_LOG_CONN_ID, new_acki);
    conn->ifc_max_ack_packno[pns] = packet_in->pi_packno;
    new_acki->pns = pns;
    if (pns != PNS_APP) /* Don't bother optimizing non-APP */
        goto process_ack;

    if (conn->ifc_flags & IFC_HAVE_SAVED_ACK)
    {
        LSQ_DEBUG("old ack [%"PRIu64"-%"PRIu64"]",
            conn->ifc_saved_ack_info.sai_range.high,
            conn->ifc_saved_ack_info.sai_range.low);
        const int is_superset = new_ack_is_superset(&conn->ifc_saved_ack_info,
                                                    new_acki);
        const int is_1range = new_acki->n_ranges == 1;
        switch (
             (is_superset << 1)
                      | (is_1range << 0))
           /* |          |
              |          |
              V          V                      */ {
        case (0 << 1) | (0 << 0):
            if (!merge_saved_to_new(&conn->ifc_saved_ack_info, new_acki))
                process_saved_ack(conn, 1);
            conn->ifc_flags &= ~IFC_HAVE_SAVED_ACK;
            if (0 != process_ack(conn, new_acki, packet_in->pi_received))
                goto err;
            break;
        case (0 << 1) | (1 << 0):
            if (!merge_new_to_saved(&conn->ifc_saved_ack_info, new_acki))
            {
                process_saved_ack(conn, 1);
                conn->ifc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
                conn->ifc_saved_ack_info.sai_range        = new_acki->ranges[0];
            }
            conn->ifc_saved_ack_info.sai_lack_delta   = new_acki->lack_delta;
            conn->ifc_saved_ack_received              = packet_in->pi_received;
            break;
        case (1 << 1) | (0 << 0):
            conn->ifc_flags &= ~IFC_HAVE_SAVED_ACK;
            if (0 != process_ack(conn, new_acki, packet_in->pi_received))
                goto err;
            break;
        case (1 << 1) | (1 << 0):
            conn->ifc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
            conn->ifc_saved_ack_info.sai_lack_delta   = new_acki->lack_delta;
            conn->ifc_saved_ack_info.sai_range        = new_acki->ranges[0];
            conn->ifc_saved_ack_received              = packet_in->pi_received;
            break;
        }
    }
    else if (new_acki->n_ranges == 1)
    {
        conn->ifc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
        conn->ifc_saved_ack_info.sai_n_timestamps = new_acki->n_timestamps;
        conn->ifc_saved_ack_info.sai_lack_delta   = new_acki->lack_delta;
        conn->ifc_saved_ack_info.sai_range        = new_acki->ranges[0];
        conn->ifc_saved_ack_received              = packet_in->pi_received;
        conn->ifc_flags |= IFC_HAVE_SAVED_ACK;
    }
    else
    {
  process_ack:
        if (0 != process_ack(conn, new_acki, packet_in->pi_received))
            goto err;
    }

    return parsed_len;

  err:
    LSQ_WARN("Invalid ACK frame");
    return 0;
}


static unsigned
process_ping_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{   /* This frame causes ACK frame to be queued, but nothing to do here;
     * return the length of this frame.
     */
    EV_LOG_PING_FRAME_IN(LSQUIC_LOG_CONN_ID);
    LSQ_DEBUG("received PING");
    return 1;
}


static unsigned
process_connection_close_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    lsquic_stream_t *stream;
    struct lsquic_hash_elem *el;
    unsigned error_code;
    uint16_t reason_len;
    uint8_t reason_off;
    int parsed_len, app_error;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_connect_close_frame(p, len,
                            &app_error, &error_code, &reason_len, &reason_off);
    if (parsed_len < 0)
        return 0;
    EV_LOG_CONNECTION_CLOSE_FRAME_IN(LSQUIC_LOG_CONN_ID, error_code,
                            (int) reason_len, (const char *) p + reason_off);
    LSQ_INFO("Received CONNECTION_CLOSE frame (%s-level code: %u; "
            "reason: %.*s)", app_error ? "application" : "transport",
                error_code, (int) reason_len, (const char *) p + reason_off);
    conn->ifc_flags |= IFC_RECV_CLOSE;
    if (!(conn->ifc_flags & IFC_CLOSING))
    {
        for (el = lsquic_hash_first(conn->ifc_pub.all_streams); el;
                             el = lsquic_hash_next(conn->ifc_pub.all_streams))
        {
            stream = lsquic_hashelem_getdata(el);
            lsquic_stream_shutdown_internal(stream);
        }
        conn->ifc_flags |= IFC_CLOSING;
    }
    return parsed_len;
}


static unsigned
process_max_data_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    uint64_t max_data;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_max_data(p, len, &max_data);
    if (parsed_len < 0)
        return 0;

    if (max_data > conn->ifc_pub.conn_cap.cc_max)
    {
        LSQ_DEBUG("max data goes from %"PRIu64" to %"PRIu64,
                                conn->ifc_pub.conn_cap.cc_max, max_data);
        conn->ifc_pub.conn_cap.cc_max = max_data;
    }
    else
        LSQ_DEBUG("newly supplied max data=%"PRIu64" is not larger than the "
            "current value=%"PRIu64", ignoring", max_data,
                                conn->ifc_pub.conn_cap.cc_max);
    return parsed_len;
}


static unsigned
process_max_stream_data_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;
    uint64_t max_data;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_max_stream_data_frame(p, len,
                                                            &stream_id, &max_data);
    if (parsed_len < 0)
        return 0;

    stream = find_stream_by_id(conn, stream_id);
    if (stream)
        lsquic_stream_window_update(stream, max_data);
    else
        LSQ_DEBUG("cannot find stream %"PRIu64" to update its max data "
            "to %"PRIu64": ignoring", stream_id, max_data);

    return parsed_len;
}


static unsigned
process_max_streams_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    lsquic_stream_id_t max_stream_id;
    enum stream_id_type sit;
    enum stream_dir sd;
    uint64_t max_streams;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_max_streams_frame(p, len,
                                                            &sd, &max_streams);
    if (parsed_len < 0)
        return 0;

    sit = gen_sit(conn->ifc_flags & IFC_SERVER, sd);
    max_stream_id = (max_streams << SIT_SHIFT) | sit;
    if (max_stream_id > conn->ifc_max_allowed_stream_id[sit])
    {
        LSQ_DEBUG("max %s stream ID updated from %"PRIu64" to %"PRIu64,
            sd == SD_BIDI ? "bidi" : "uni",
            conn->ifc_max_allowed_stream_id[sit], max_stream_id);
        conn->ifc_max_allowed_stream_id[sit] = max_stream_id;
    }
    else
        LSQ_DEBUG("ignore old max %s streams value of %"PRIu64,
            sd == SD_BIDI ? "bidi" : "uni", max_streams);

    return parsed_len;
}


static unsigned
process_new_connection_id_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct dcid_elem **dce, **el;
    const unsigned char *token;
    const char *action_str;
    lsquic_cid_t cid;
    uint64_t seqno;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_new_conn_id(p, len, &seqno,
                                                                &cid, &token);
    if (parsed_len < 0)
        return 0;

    dce = NULL;
    for (el = conn->ifc_dces; el < conn->ifc_dces + sizeof(conn->ifc_dces)
                                            / sizeof(conn->ifc_dces[0]); ++el)
        if (*el)
        {
            if ((*el)->de_seqno == seqno)
            {
                if (!LSQUIC_CIDS_EQ(&(*el)->de_cid, &cid))
                {
                    ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                        "NEW_CONNECTION_ID: already have CID seqno %"PRIu64
                        " but with a different CID", seqno);
                    return 0;
                }
            }
            else if (LSQUIC_CIDS_EQ(&(*el)->de_cid, &cid))
            {
                ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                    "NEW_CONNECTION_ID: received the same CID with sequence "
                    "numbers %u and %"PRIu64, (*el)->de_seqno, seqno);
                return 0;
            }
        }
        else if (!dce)
            dce = el;

    if (dce)
    {
        *dce = lsquic_malo_get(conn->ifc_pub.mm->malo.dcid_elem);
        if (*dce)
        {
            memset(*dce, 0, sizeof(**dce));
            (*dce)->de_seqno = seqno;
            (*dce)->de_cid = cid;
            memcpy((*dce)->de_srst, token, sizeof((*dce)->de_srst));
            (*dce)->de_flags |= DE_SRST;
            action_str = "Saved";
        }
        else
            action_str = "Ignored (alloc failure)";
    }
    else
        action_str = "Ignored (no slots available)";

    LSQ_DEBUGC("Got new connection ID from peer: seq=%"PRIu64"; "
        "cid: %"CID_FMT".  %s.", seqno, CID_BITS(&cid), action_str);
    return parsed_len;
}


static unsigned
process_retire_connection_id_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;
    struct conn_cid_elem *cce;
    uint64_t seqno;
    int parsed_len;

    /* [draft-ietf-quic-transport-16] Section 19.13 */
    if (conn->ifc_settings->es_scid_len == 0)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "cannot retire zero-length CID");
        return 0;
    }

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_retire_cid_frame(p, len,
                                                                    &seqno);
    if (parsed_len < 0)
        return 0;

    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "got RETIRE_CONNECTION_ID frame: "
                                                        "seqno=%"PRIu64, seqno);
    /* [draft-ietf-quic-transport-16] Section 19.13 */
    if (seqno >= conn->ifc_scid_seqno)
    {
        ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION, "cannot retire CID seqno="
                        "%"PRIu64" as it has not been allocated yet", seqno);
        return 0;
    }

    for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
        if ((lconn->cn_cces_mask & (1 << (cce - lconn->cn_cces))
                && cce->cce_seqno == seqno))
            break;

    if (cce >= END_OF_CCES(lconn))
    {
        LSQ_DEBUG("cannot retire CID seqno=%"PRIu64": not found", seqno);
        return parsed_len;
    }

    LSQ_DEBUGC("retiring CID %"CID_FMT"; seqno: %u; is current: %d",
        CID_BITS(&cce->cce_cid), cce->cce_seqno,
        seqno == lconn->cn_cur_cce_idx);
    lsquic_engine_retire_cid(conn->ifc_enpub, lconn, cce - lconn->cn_cces,
                                                        packet_in->pi_received);
    memset(cce, 0, sizeof(*cce));

    if ((1 << conn->ifc_conn.cn_n_cces) - 1 != conn->ifc_conn.cn_cces_mask)
        conn->ifc_send_flags |= SF_SEND_NEW_CID;

    if (seqno == lconn->cn_cur_cce_idx)
    {
        /* When current connection ID is retired, we need to pick the new
         * current CCE index.  We prefer a CCE that's already been used
         * with the lowest sequence number; failing that, we prefer a CCE
         * with the lowest sequence number.
         */
        const struct conn_cid_elem *cces[2] = { NULL, NULL, };

        LSQ_DEBUG("retired current connection ID without DCID change: odd");

        for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
        {
            if (lconn->cn_cces_mask & (1 << (cce - lconn->cn_cces)))
            {
                if (cce->cce_flags & CCE_USED)
                {
                    if (cces[0])
                    {
                        if (cce->cce_seqno < cces[0]->cce_seqno)
                            cces[0] = cce;
                    }
                    else
                        cces[0] = cce;
                }
                if (cces[1])
                {
                    if (cce->cce_seqno < cces[1]->cce_seqno)
                        cces[1] = cce;
                }
                else
                    cces[1] = cce;
            }
        }

        if (cces[0] || cces[1])
        {
            lconn->cn_cur_cce_idx = (cces[0] ? cces[0] : cces[1])
                                                            - lconn->cn_cces;
            lconn->cn_cces[lconn->cn_cur_cce_idx].cce_flags |= CCE_USED;
            LSQ_DEBUG("set current CCE index to %u", lconn->cn_cur_cce_idx);
        }
        else
        {
            /* XXX This is a corner case: this connection is no longer
             * reachable.  Perhaps we could simply close it instead of
             * waiting for it to time out.
             */
            lconn->cn_cur_cce_idx = 0;
            LSQ_INFO("last SCID retired; set current CCE index to 0");
        }
    }

    return parsed_len;
}


static unsigned
process_new_token_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    const unsigned char *token;
    size_t token_sz;
    char *token_str;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_new_token_frame(p, len, &token,
                                                                    &token_sz);
    if (parsed_len < 0)
        return 0;

    if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG)
                            || LSQ_LOG_ENABLED_EXT(LSQ_LOG_DEBUG, LSQLM_EVENT))
    {
        token_str = malloc(token_sz * 2 + 1);
        if (token_str)
        {
            lsquic_hexstr(token, token_sz, token_str, token_sz * 2 + 1);
            LSQ_DEBUG("Got %zu-byte NEW_TOKEN %s", token_sz, token_str);
            EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "got NEW_TOKEN %s",
                                                                    token_str);
            free(token_str);
        }
    }
    if (conn->ifc_stream_if->on_new_token)
        conn->ifc_stream_if->on_new_token(conn->ifc_stream_ctx, token,
                                                                    token_sz);
    return parsed_len;
}


static unsigned
process_stream_blocked_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    struct lsquic_stream *stream;
    lsquic_stream_id_t stream_id;
    uint64_t peer_off;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_stream_blocked_frame(p,
                                                len, &stream_id, &peer_off);
    if (parsed_len < 0)
        return 0;

    LSQ_DEBUG("received STREAM_BLOCKED frame: stream %"PRIu64
                                    "; offset %"PRIu64, stream_id, peer_off);
    stream = find_stream_by_id(conn, stream_id);
    if (stream)
        lsquic_stream_peer_blocked(stream, peer_off);
    else
        LSQ_DEBUG("stream %"PRIu64" not found - ignore STREAM_BLOCKED frame",
            stream_id);
    return parsed_len;
}


static unsigned
process_blocked_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    uint64_t off;
    int parsed_len;

    parsed_len = conn->ifc_conn.cn_pf->pf_parse_blocked_frame(p, len, &off);
    if (parsed_len < 0)
        return 0;

    LSQ_DEBUG("received BLOCKED frame: offset %"PRIu64, off);
    /* XXX Try to do something? */
    return parsed_len;
}


/* XXX This frame will be gone in ID-17, don't implement it just yet. */
static unsigned
process_GONE_IN_ID_17 (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    uint64_t val;
    int parsed_len;

    LSQ_DEBUG("Ignore frame value");
    parsed_len = conn->ifc_conn.cn_pf->pf_parse_blocked_frame(p, len, &val);
    if (parsed_len < 0)
        return 0;
    else
        return parsed_len;
}


typedef unsigned (*process_frame_f)(
    struct ietf_full_conn *, struct lsquic_packet_in *,
    const unsigned char *p, size_t);


static process_frame_f const process_frames[N_QUIC_FRAMES] =
{
    [QUIC_FRAME_PADDING]            =  process_padding_frame,
    [QUIC_FRAME_RST_STREAM]         =  process_rst_stream_frame,
    [QUIC_FRAME_CONNECTION_CLOSE]   =  process_connection_close_frame,
    [QUIC_FRAME_MAX_DATA]           =  process_max_data_frame,
    [QUIC_FRAME_MAX_STREAM_DATA]    =  process_max_stream_data_frame,
    [QUIC_FRAME_MAX_STREAMS]        =  process_max_streams_frame,
    [QUIC_FRAME_PING]               =  process_ping_frame,
    [QUIC_FRAME_BLOCKED]            =  process_blocked_frame,
    [QUIC_FRAME_STREAM_BLOCKED]     =  process_stream_blocked_frame,
    [QUIC_FRAME_STREAM_ID_BLOCKED]  =  process_GONE_IN_ID_17,
    [QUIC_FRAME_NEW_CONNECTION_ID]  =  process_new_connection_id_frame,
    [QUIC_FRAME_NEW_TOKEN]          =  process_new_token_frame,
    [QUIC_FRAME_STOP_SENDING]       =  process_stop_sending_frame,
    [QUIC_FRAME_ACK]                =  process_ack_frame,
    [QUIC_FRAME_PATH_CHALLENGE]     =  process_path_challenge_frame,
    [QUIC_FRAME_PATH_RESPONSE]      =  process_path_response_frame,
    [QUIC_FRAME_RETIRE_CONNECTION_ID] =  process_retire_connection_id_frame,
    [QUIC_FRAME_STREAM]             =  process_stream_frame,
    [QUIC_FRAME_CRYPTO]             =  process_crypto_frame,
};


static unsigned
process_packet_frame (struct ietf_full_conn *conn,
        struct lsquic_packet_in *packet_in, const unsigned char *p, size_t len)
{
    enum enc_level enc_level = lsquic_packet_in_enc_level(packet_in);
    enum quic_frame_type type = conn->ifc_conn.cn_pf->pf_parse_frame_type(p[0]);
    if (lsquic_legal_frames_by_level[enc_level] & (1 << type))
    {
        LSQ_DEBUG("about to process %s frame", frame_type_2_str[type]);
        packet_in->pi_frame_types |= 1 << type;
        return process_frames[type](conn, packet_in, p, len);
    }
    else
    {
        LSQ_DEBUG("invalid frame %u (byte=0x%02X) at encryption level %s",
                                    type, p[0], lsquic_enclev2str[enc_level]);
        return 0;
    }
}


static void
parse_regular_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    const unsigned char *p, *pend;
    unsigned len;

    p = packet_in->pi_data + packet_in->pi_header_sz;
    pend = packet_in->pi_data + packet_in->pi_data_sz;

    while (p < pend)
    {
        len = process_packet_frame(conn, packet_in, p, pend - p);
        if (len > 0)
            p += len;
        else
        {
            ABORT_ERROR("Error parsing frame");
            break;
        }
    }
}


static void
try_queueing_ack (struct ietf_full_conn *conn, enum packnum_space pns,
                                            int was_missing, lsquic_time_t now)
{
    if (conn->ifc_n_slack_akbl[pns] >= MAX_RETR_PACKETS_SINCE_LAST_ACK ||
        ((conn->ifc_flags & IFC_ACK_HAD_MISS) && was_missing)      ||
        lsquic_send_ctl_n_stop_waiting(&conn->ifc_send_ctl, pns) > 1)
    {
        lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_INIT + pns)
        lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
        conn->ifc_flags |= IFC_ACK_QUED_INIT << pns;
        LSQ_DEBUG("%s ACK queued: ackable: %u; had_miss: %d; "
            "was_missing: %d; n_stop_waiting: %u",
            lsquic_pns2str[pns], conn->ifc_n_slack_akbl[pns],
            !!(conn->ifc_flags & IFC_ACK_HAD_MISS), was_missing,
            lsquic_send_ctl_n_stop_waiting(&conn->ifc_send_ctl, pns));
    }
    else if (conn->ifc_n_slack_akbl[pns] > 0)
    {
/* [draft-ietf-quic-transport-15] Section-7.16.3:
 *
 * The receiver's delayed acknowledgment timer SHOULD NOT exceed the
 * current RTT estimate or the value it indicates in the "max_ack_delay"
 * transport parameter
 *
 * TODO: Need to do MIN(ACK_TIMEOUT, RTT Estimate)
 */
        lsquic_alarmset_set(&conn->ifc_alset, AL_ACK_INIT + pns,
                                                        now + ACK_TIMEOUT);
        LSQ_DEBUG("%s ACK alarm set to %"PRIu64, lsquic_pns2str[pns],
                                                        now + ACK_TIMEOUT);
    }
}


static int
process_retry_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    int cidlen_diff;

    if (conn->ifc_flags & (IFC_SERVER|IFC_RETRIED))
    {
        LSQ_DEBUG("ignore Retry packet");
        return 0;
    }

    if (!(conn->ifc_conn.cn_dcid.len == packet_in->pi_odcid_len
            && 0 == memcmp(conn->ifc_conn.cn_dcid.idbuf,
                            packet_in->pi_data + packet_in->pi_odcid,
                            packet_in->pi_odcid_len)))
    {
        LSQ_DEBUG("retry packet's ODCID does not match the original: ignore");
        return 0;
    }

    cidlen_diff = (int) conn->ifc_conn.cn_dcid.len
                                        - (int) packet_in->pi_scid.len;
    if (0 != lsquic_send_ctl_retry(&conn->ifc_send_ctl,
                    packet_in->pi_data + packet_in->pi_token,
                            packet_in->pi_token_size, cidlen_diff))
        return -1;

    if (0 != conn->ifc_conn.cn_esf.i->esfi_reset_dcid(
                        conn->ifc_conn.cn_enc_session, &packet_in->pi_scid))
        return -1;

    LSQ_INFO("Received a retry packet.  Will retry.");
    conn->ifc_flags |= IFC_RETRIED;
    return 0;
}


static int
is_stateless_reset (struct ietf_full_conn *conn,
                                    const struct lsquic_packet_in *packet_in)
{
    struct lsquic_hash_elem *el;

    if (packet_in->pi_data_sz < IQUIC_MIN_SRST_SIZE)
        return 0;

    el = lsquic_hash_find(conn->ifc_enpub->enp_srst_hash,
            packet_in->pi_data + packet_in->pi_data_sz - IQUIC_SRESET_TOKEN_SZ,
            IQUIC_SRESET_TOKEN_SZ);
    if (!el)
        return 0;

#ifndef NDEBUG
    const struct lsquic_conn *reset_lconn;
    reset_lconn = lsquic_hashelem_getdata(el);
    assert(reset_lconn == &conn->ifc_conn);
#endif
    return 1;
}


/* From [draft-ietf-quic-transport-16, Section-9.5:
 *
 * Caution:  If both endpoints change connection ID in response to
 *    seeing a change in connection ID from their peer, then this can
 *    trigger an infinite sequence of changes.
 *
 * XXX Add flag to only switch DCID if we weren't the initiator.
 */
/* This function does two things:
 *  1. Sets the new current SCID if the DCID in the incoming packet has not
 *          been used before; and
 *  2. Initiates its own switch to a new DCID if there are any.
 */
static int
on_dcid_change (struct ietf_full_conn *conn, const lsquic_cid_t *dcid_in)
{
    struct lsquic_conn *const lconn = &conn->ifc_conn;  /* Shorthand */
    struct conn_cid_elem *cce;
    struct dcid_elem **el, **dces[2];
    int eq;

    LSQ_DEBUG("peer switched DCID");

    for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
        if (cce - lconn->cn_cces != lconn->cn_cur_cce_idx
                && (lconn->cn_cces_mask & (1 << (cce - lconn->cn_cces)))
                    && LSQUIC_CIDS_EQ(&cce->cce_cid, dcid_in))
            break;

    if (cce >= END_OF_CCES(lconn))
    {
        ABORT_WARN("new DCID not found");
        return -1;
    }

    if (cce->cce_flags & CCE_USED)
    {
        LSQ_DEBUGC("non-matching new DCID %"CID_FMT" has already been used, "
            "not switching DCID", CID_BITS(dcid_in));
        return 0;
    }

    cce->cce_flags |= CCE_USED;
    lconn->cn_cur_cce_idx = cce - lconn->cn_cces;
    LSQ_DEBUGC("on DCID change: set current SCID to %"CID_FMT,
                                                    CID_BITS(CN_SCID(lconn)));

    /* Part II: initiate own DCID switch */

    dces[0] = NULL;
    dces[1] = NULL;
    for (el = conn->ifc_dces; el < conn->ifc_dces + sizeof(conn->ifc_dces)
                    / sizeof(conn->ifc_dces[0]) && !(dces[0] && dces[1]); ++el)
        if (*el)
        {
            eq = LSQUIC_CIDS_EQ(&(*el)->de_cid, &lconn->cn_dcid);
            if (!dces[eq])
                dces[eq] = el;
        }

    if (!dces[1])
    {
        ABORT_WARN("%s: cannot find own DCID", __func__);
        return -1;
    }

    if (!dces[0])
    {
        LSQ_INFO("No DCID available: cannot switch");
        /* TODO: implemened delayed switch */
        conn->ifc_flags |= IFC_SWITCH_DCID;
        return 0;
    }

    lconn->cn_dcid = (*dces[0])->de_cid;
    LSQ_INFOC("switched DCID to %"CID_FMT, CID_BITS(&lconn->cn_dcid));

    if ((*dces[1])->de_hash_el.qhe_flags & QHE_HASHED)
        lsquic_hash_erase(conn->ifc_enpub->enp_srst_hash,
                                                &(*dces[1])->de_hash_el);
    TAILQ_INSERT_TAIL(&conn->ifc_to_retire, *dces[1], de_next_to_ret);
    dces[1] = NULL;
    conn->ifc_send_flags |= SF_SEND_RETIRE_CID;

    return 0;
}


static void
ignore_init (struct ietf_full_conn *conn)
{
    LSQ_DEBUG("henceforth, no Initial packets shall be sent or received");
    conn->ifc_flags |= IFC_IGNORE_INIT;
    conn->ifc_flags &= ~(IFC_ACK_QUED_INIT << PNS_INIT);
    lsquic_alarmset_unset(&conn->ifc_alset, AL_ACK_INIT + PNS_INIT);
    lsquic_send_ctl_empty_pns(&conn->ifc_send_ctl, PNS_INIT);
    lsquic_rechist_cleanup(&conn->ifc_rechist[PNS_INIT]);
    if (conn->ifc_crypto_streams[ENC_LEV_CLEAR])
    {
        lsquic_stream_destroy(conn->ifc_crypto_streams[ENC_LEV_CLEAR]);
        conn->ifc_crypto_streams[ENC_LEV_CLEAR] = NULL;
    }
}


static int
process_regular_packet (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    enum packnum_space pns;
    enum received_st st;
    enum dec_packin dec_packin;
    enum quic_ft_bit frame_types;
    int was_missing;

    if (HETY_RETRY == packet_in->pi_header_type)
        return process_retry_packet(conn, packet_in);

    pns = lsquic_hety2pns[ packet_in->pi_header_type ];
    if (pns == PNS_INIT && (conn->ifc_flags & IFC_IGNORE_INIT))
    {
        LSQ_DEBUG("ignore init packet");    /* Don't bother decrypting */
        return 0;
    }

    /* The packet is decrypted before receive history is updated.  This is
     * done to make sure that a bad packet won't occupy a slot in receive
     * history and subsequent good packet won't be marked as a duplicate.
     */
    if (0 == (packet_in->pi_flags & PI_DECRYPTED))
    {
        dec_packin = conn->ifc_conn.cn_esf_c->esf_decrypt_packet(
                        conn->ifc_conn.cn_enc_session, conn->ifc_enpub,
                        &conn->ifc_conn, packet_in);
        switch (dec_packin)
        {
        case DECPI_BADCRYPT:
            if (conn->ifc_enpub->enp_settings.es_honor_prst
                                        && is_stateless_reset(conn, packet_in))
            {
                LSQ_INFO("received stateless reset packet: aborting connection");
                conn->ifc_flags |= IFC_GOT_PRST;
                return -1;
            }
            else
            {
                LSQ_INFO("could not decrypt packet (type %s)",
                                    lsquic_hety2str[packet_in->pi_header_type]);
                return 0;
            }
        case DECPI_NOT_YET:
            return 0;
        case DECPI_NOMEM:
            return 0;
        case DECPI_TOO_SHORT:
            /* We should not hit this path: packets that are too short should
             * not be parsed correctly.
             */
            LSQ_INFO("packet is too short to be decrypted");
            return 0;
        case DECPI_VIOLATION:
            ABORT_QUIETLY(0, TEC_PROTOCOL_VIOLATION,
                                    "decrypter reports protocol violation");
            return -1;
        case DECPI_OK:
            break;
        }
    }

    EV_LOG_PACKET_IN(LSQUIC_LOG_CONN_ID, packet_in);

    st = lsquic_rechist_received(&conn->ifc_rechist[pns], packet_in->pi_packno,
                                                    packet_in->pi_received);
    switch (st) {
    case REC_ST_OK:
        if (!(conn->ifc_flags & (
                                            IFC_DCID_SET))
                                                && (packet_in->pi_scid.len))
        {
            conn->ifc_flags |= IFC_DCID_SET;
            conn->ifc_conn.cn_dcid = packet_in->pi_scid;
            LSQ_DEBUGC("set DCID to %"CID_FMT,
                                        CID_BITS(&conn->ifc_conn.cn_dcid));
        }
        if (!LSQUIC_CIDS_EQ(CN_SCID(&conn->ifc_conn), &packet_in->pi_dcid))
        {
            if (0 != on_dcid_change(conn, &packet_in->pi_dcid))
                return -1;
        }
        parse_regular_packet(conn, packet_in);
        if (0 == (conn->ifc_flags & (IFC_ACK_QUED_INIT << pns)))
        {
            frame_types = packet_in->pi_frame_types;
#if 0   /* TODO */
#endif
            was_missing = packet_in->pi_packno !=
                        lsquic_rechist_largest_packno(&conn->ifc_rechist[pns]);
            conn->ifc_n_slack_akbl[pns]
                                += !!(frame_types & IQUIC_FRAME_ACKABLE_MASK);
            try_queueing_ack(conn, pns, was_missing, packet_in->pi_received);
        }
        conn->ifc_incoming_ecn <<= 1;
        conn->ifc_incoming_ecn |=
                            lsquic_packet_in_ecn(packet_in) != ECN_NOT_ECT;
        ++conn->ifc_ecn_counts_in[pns][ lsquic_packet_in_ecn(packet_in) ];
        return 0;
    case REC_ST_DUP:
        LSQ_INFO("packet %"PRIu64" is a duplicate", packet_in->pi_packno);
        return 0;
    default:
        assert(0);
        /* Fall through */
    case REC_ST_ERR:
        LSQ_INFO("error processing packet %"PRIu64, packet_in->pi_packno);
        return -1;
    }
}


/* This function is used by the client when version negotiation is not yet
 * complete.
 */
static int
process_incoming_packet_verneg (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    int s;
    struct ver_iter vi;
    lsquic_ver_tag_t ver_tag;
    enum lsquic_version version;
    unsigned versions;

    if (lsquic_packet_in_is_verneg(packet_in))
    {
        /* TODO: verify source connection ID, see
         *  [draft-ietf-quic-transport-11], Section 4.3.
         */
        LSQ_DEBUG("Processing version-negotiation packet");

        if (conn->ifc_ver_neg.vn_state != VN_START)
        {
            LSQ_DEBUG("ignore a likely duplicate version negotiation packet");
            return 0;
        }

        versions = 0;
        for (s = packet_in_ver_first(packet_in, &vi, &ver_tag); s;
                         s = packet_in_ver_next(&vi, &ver_tag))
        {
            version = lsquic_tag2ver(ver_tag);
            if (version < N_LSQVER)
            {
                versions |= 1 << version;
                LSQ_DEBUG("server supports version %s", lsquic_ver2str[version]);
            }
        }

        if (versions & (1 << conn->ifc_ver_neg.vn_ver))
        {
            ABORT_ERROR("server replied with version we support: %s",
                                        lsquic_ver2str[conn->ifc_ver_neg.vn_ver]);
            return -1;
        }

        versions &= conn->ifc_ver_neg.vn_supp;
        if (0 == versions)
        {
            ABORT_ERROR("client does not support any of the server-specified "
                        "versions");
            return -1;
        }

        set_versions(conn, versions);
        conn->ifc_ver_neg.vn_state = VN_IN_PROGRESS;
        lsquic_send_ctl_expire_all(&conn->ifc_send_ctl);
        return 0;
    }

    assert(conn->ifc_ver_neg.vn_tag);
    assert(conn->ifc_ver_neg.vn_state != VN_END);
    conn->ifc_ver_neg.vn_state = VN_END;
    conn->ifc_ver_neg.vn_tag = NULL;
    conn->ifc_conn.cn_version = conn->ifc_ver_neg.vn_ver;
    conn->ifc_conn.cn_flags |= LSCONN_VER_SET;
    LSQ_DEBUG("end of version negotiation: agreed upon %s",
                            lsquic_ver2str[conn->ifc_ver_neg.vn_ver]);
    conn->ifc_process_incoming_packet = process_incoming_packet_fast;

    return process_regular_packet(conn, packet_in);
}


/* This function is used after version negotiation is completed */
static int
process_incoming_packet_fast (struct ietf_full_conn *conn,
                                        struct lsquic_packet_in *packet_in)
{
    return process_regular_packet(conn, packet_in);
}


static void
ietf_full_conn_ci_packet_in (struct lsquic_conn *lconn,
                             struct lsquic_packet_in *packet_in)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;

    lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE,
                packet_in->pi_received + conn->ifc_settings->es_idle_conn_to);
    if (0 == (conn->ifc_flags & IFC_IMMEDIATE_CLOSE_FLAGS))
        if (0 != conn->ifc_process_incoming_packet(conn, packet_in))
            conn->ifc_flags |= IFC_ERROR;
}


static void
ietf_full_conn_ci_packet_not_sent (struct lsquic_conn *lconn,
                                   struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    lsquic_send_ctl_delayed_one(&conn->ifc_send_ctl, packet_out);
}


static void
ietf_full_conn_ci_packet_sent (struct lsquic_conn *lconn,
                               struct lsquic_packet_out *packet_out)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    int s;

    if (packet_out->po_frame_types & GQUIC_FRAME_RETRANSMITTABLE_MASK)
    {
        conn->ifc_n_cons_unretx = 0;
        lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE,
                    packet_out->po_sent + conn->ifc_settings->es_idle_conn_to);
    }
    else
        ++conn->ifc_n_cons_unretx;
    s = lsquic_send_ctl_sent_packet(&conn->ifc_send_ctl, packet_out);
    if (s != 0)
        ABORT_ERROR("sent packet failed: %s", strerror(errno));
    ++conn->ifc_ecn_counts_out[ lsquic_packet_out_pns(packet_out) ]
                              [ lsquic_packet_out_ecn(packet_out) ];
    if (0 == (conn->ifc_flags & IFC_IGNORE_INIT))
    {
        if (PNS_HSK == lsquic_packet_out_pns(packet_out))
            ignore_init(conn);
    }
}


static enum tick_st
ietf_full_conn_ci_tick (struct lsquic_conn *lconn, lsquic_time_t now)
{
    struct ietf_full_conn *conn = (struct ietf_full_conn *) lconn;
    const struct lsquic_stream *highest_non_crit;
    int have_delayed_packets, s;
    enum tick_st tick = 0;
    unsigned n;

#define CLOSE_IF_NECESSARY() do {                                       \
    if (conn->ifc_flags & IFC_IMMEDIATE_CLOSE_FLAGS)                    \
    {                                                                   \
        tick |= immediate_close(conn);                                  \
        goto close_end;                                                 \
    }                                                                   \
} while (0)

#define RETURN_IF_OUT_OF_PACKETS() do {                                 \
    if (!lsquic_send_ctl_can_send(&conn->ifc_send_ctl))                 \
    {                                                                   \
        if (0 == lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl))      \
        {                                                               \
            LSQ_DEBUG("used up packet allowance, quiet now (line %d)",  \
                __LINE__);                                              \
            tick |= TICK_QUIET;                                         \
        }                                                               \
        else                                                            \
        {                                                               \
            LSQ_DEBUG("used up packet allowance, sending now (line %d)",\
                __LINE__);                                              \
            tick |= TICK_SEND;                                          \
        }                                                               \
        goto end;                                                       \
    }                                                                   \
} while (0)

    if (conn->ifc_flags & IFC_HAVE_SAVED_ACK)
    {
        (void) /* If there is an error, we'll fail shortly */
            process_saved_ack(conn, 0);
        conn->ifc_flags &= ~IFC_HAVE_SAVED_ACK;
    }

    lsquic_send_ctl_tick(&conn->ifc_send_ctl, now);
    lsquic_send_ctl_set_buffer_stream_packets(&conn->ifc_send_ctl, 1);
    CLOSE_IF_NECESSARY();

    lsquic_alarmset_ring_expired(&conn->ifc_alset, now);
    CLOSE_IF_NECESSARY();

    /* To make things simple, only stream 1 is active until the handshake
     * has been completed.  This will be adjusted in the future: the client
     * does not want to wait if it has the server information.
     */
    if (conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE)
        process_streams_read_events(conn);
    else
        process_crypto_stream_read_events(conn);
    CLOSE_IF_NECESSARY();

    if (lsquic_send_ctl_pacer_blocked(&conn->ifc_send_ctl))
        goto end_write;

    /* If there are any scheduled packets at this point, it means that
     * they were not sent during previous tick; in other words, they
     * are delayed.  When there are delayed packets, the only packet
     * we sometimes add is a packet with an ACK frame, and we add it
     * to the *front* of the queue.
     */
    have_delayed_packets =
        lsquic_send_ctl_maybe_squeeze_sched(&conn->ifc_send_ctl);

    if (should_generate_ack(conn))
    {
        if (have_delayed_packets)
            lsquic_send_ctl_reset_packnos(&conn->ifc_send_ctl);

        /* ACK frame generation fails with an error if it does not fit into
         * a single packet (it always should fit).
         * XXX Is this still true?
         */
        generate_ack_frame(conn);
        CLOSE_IF_NECESSARY();

        if (have_delayed_packets)
            lsquic_send_ctl_ack_to_front(&conn->ifc_send_ctl);
    }

    if (have_delayed_packets)
    {
        /* The reason for not adding the other frames below to the packet
         * carrying ACK frame generated when there are delayed packets is
         * so that if the ACK packet itself is delayed, it can be dropped
         * and replaced by new ACK packet.  This way, we are never more
         * than 1 packet over CWND.
         */
        tick |= TICK_SEND;
        goto end;
    }

    /* Try to fit MAX_DATA before checking if we have run out of room.
     * If it does not fit, it will be tried next time around.
     */
    if (lsquic_cfcw_fc_offsets_changed(&conn->ifc_pub.cfcw) ||
                                (conn->ifc_send_flags & SF_SEND_MAX_DATA))
    {
        conn->ifc_send_flags |= SF_SEND_MAX_DATA;
        generate_max_data_frame(conn);
        CLOSE_IF_NECESSARY();
    }

    if (conn->ifc_send_flags)
    {
        if (conn->ifc_send_flags & SF_SEND_NEW_CID)
        {
            generate_new_cid_frames(conn);
            CLOSE_IF_NECESSARY();
        }
        if (conn->ifc_send_flags & SF_SEND_RETIRE_CID)
        {
            generate_retire_cid_frames(conn);
            CLOSE_IF_NECESSARY();
        }
    }

    n = lsquic_send_ctl_reschedule_packets(&conn->ifc_send_ctl);
    if (n > 0)
        CLOSE_IF_NECESSARY();

    RETURN_IF_OUT_OF_PACKETS();

    if (conn->ifc_conn.cn_flags & LSCONN_SEND_BLOCKED)
    {
        if (generate_blocked_frame(conn))
            conn->ifc_conn.cn_flags &= ~LSCONN_SEND_BLOCKED;
        else
            RETURN_IF_OUT_OF_PACKETS();
    }

    if (!STAILQ_EMPTY(&conn->ifc_stream_ids_to_reset))
    {
        packetize_standalone_stream_resets(conn);
        CLOSE_IF_NECESSARY();
    }

    if (!TAILQ_EMPTY(&conn->ifc_pub.sending_streams))
    {
        process_streams_ready_to_send(conn);
        CLOSE_IF_NECESSARY();
    }

    lsquic_send_ctl_set_buffer_stream_packets(&conn->ifc_send_ctl, 0);
    if (!(conn->ifc_conn.cn_flags & LSCONN_HANDSHAKE_DONE))
    {
        s = lsquic_send_ctl_schedule_buffered(&conn->ifc_send_ctl,
                                                            BPT_HIGHEST_PRIO);
        conn->ifc_flags |= (s < 0) << IFC_BIT_ERROR;
        if (0 == s)
            process_crypto_stream_write_events(conn);
        goto end_write;
    }

    maybe_conn_flush_special_streams(conn);

    s = lsquic_send_ctl_schedule_buffered(&conn->ifc_send_ctl, BPT_HIGHEST_PRIO);
    conn->ifc_flags |= (s < 0) << IFC_BIT_ERROR;
    if (!write_is_possible(conn))
        goto end_write;

    if (!TAILQ_EMPTY(&conn->ifc_pub.write_streams))
    {
        process_streams_write_events(conn, 1, &highest_non_crit);
        if (!write_is_possible(conn))
            goto end_write;
    }

    s = lsquic_send_ctl_schedule_buffered(&conn->ifc_send_ctl, BPT_OTHER_PRIO);
    conn->ifc_flags |= (s < 0) << IFC_BIT_ERROR;
    if (!write_is_possible(conn))
        goto end_write;

    if (!TAILQ_EMPTY(&conn->ifc_pub.write_streams))
        process_streams_write_events(conn, 0, &highest_non_crit);

  end_write:
    RETURN_IF_OUT_OF_PACKETS();

    if ((conn->ifc_flags & IFC_CLOSING) && conn_ok_to_close(conn))
    {
        LSQ_DEBUG("connection is OK to close");
        /* This is normal termination sequence.
         *
         * Generate CONNECTION_CLOSE frame if we are responding to one, have
         * packets scheduled to send, or silent close flag is not set.
         */
        conn->ifc_flags |= IFC_TICK_CLOSE;
        if ((conn->ifc_flags & IFC_RECV_CLOSE) ||
                0 != lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl) ||
                                        !conn->ifc_settings->es_silent_close)
        {
            if (conn->ifc_send_flags & SF_SEND_CONN_CLOSE)
                generate_connection_close_packet(conn);
            tick |= TICK_SEND|TICK_CLOSE;
        }
        else
            tick |= TICK_CLOSE;
        goto end;
    }

    if (0 == lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl))
    {
        if ((conn->ifc_send_flags & SF_SEND_PING)
                                            && 0 == generate_ping_frame(conn))
        {
            conn->ifc_send_flags &= ~SF_SEND_PING;
            CLOSE_IF_NECESSARY();
            assert(lsquic_send_ctl_n_scheduled(&conn->ifc_send_ctl) != 0);
        }
        else
        {
            tick |= TICK_QUIET;
            goto end;
        }
    }
    else
    {
        lsquic_alarmset_unset(&conn->ifc_alset, AL_PING);
        lsquic_send_ctl_sanity_check(&conn->ifc_send_ctl);
        conn->ifc_send_flags &= ~SF_SEND_PING;   /* It may have rung */
    }

    now = lsquic_time_now();
    lsquic_alarmset_set(&conn->ifc_alset, AL_IDLE,
                                now + conn->ifc_settings->es_idle_conn_to);

    /* [draft-ietf-quic-transport-11] Section 7.9:
     *
     *     The PING frame can be used to keep a connection alive when an
     *     application or application protocol wishes to prevent the connection
     *     from timing out.  An application protocol SHOULD provide guidance
     *     about the conditions under which generating a PING is recommended.
     *     This guidance SHOULD indicate whether it is the client or the server
     *     that is expected to send the PING.  Having both endpoints send PING
     *     frames without coordination can produce an excessive number of
     *     packets and poor performance.
     *
     * For now, we'll be like Google QUIC and have the client send PING frames.
     */
    if (
        lsquic_hash_count(conn->ifc_pub.all_streams) > 0)
        lsquic_alarmset_set(&conn->ifc_alset, AL_PING, now + TIME_BETWEEN_PINGS);

    tick |= TICK_SEND;

  end:
    service_streams(conn);
    CLOSE_IF_NECESSARY();

  close_end:
    lsquic_send_ctl_set_buffer_stream_packets(&conn->ifc_send_ctl, 1);
    return tick;
}


static enum LSQUIC_CONN_STATUS
ietf_full_conn_ci_status (struct lsquic_conn *lconn, char *errbuf, size_t bufsz)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    size_t n;

    /* Test the common case first: */
    if (!(conn->ifc_flags & (IFC_ERROR
                            |IFC_TIMED_OUT
                            |IFC_ABORTED
                            |IFC_GOT_PRST
                            |IFC_HSK_FAILED
                            |IFC_CLOSING
                            |IFC_GOING_AWAY)))
    {
        if (lconn->cn_flags & LSCONN_PEER_GOING_AWAY)
            return LSCONN_ST_PEER_GOING_AWAY;
        else if (lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
            return LSCONN_ST_CONNECTED;
        else
            return LSCONN_ST_HSK_IN_PROGRESS;
    }

    if (errbuf && bufsz)
    {
        if (conn->ifc_errmsg)
        {
            n = bufsz < MAX_ERRMSG ? bufsz : MAX_ERRMSG;
            strncpy(errbuf, conn->ifc_errmsg, n);
            errbuf[n - 1] = '\0';
        }
        else
            errbuf[0] = '\0';
    }

    if (conn->ifc_flags & IFC_ERROR)
        return LSCONN_ST_ERROR;
    if (conn->ifc_flags & IFC_TIMED_OUT)
        return LSCONN_ST_TIMED_OUT;
    if (conn->ifc_flags & IFC_ABORTED)
        return LSCONN_ST_USER_ABORTED;
    if (conn->ifc_flags & IFC_GOT_PRST)
        return LSCONN_ST_RESET;
    if (conn->ifc_flags & IFC_HSK_FAILED)
        return LSCONN_ST_HSK_FAILURE;
    if (conn->ifc_flags & IFC_CLOSING)
        return LSCONN_ST_CLOSED;
    assert(conn->ifc_flags & IFC_GOING_AWAY);
    return LSCONN_ST_GOING_AWAY;
}


static void
ietf_full_conn_ci_stateless_reset (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    conn->ifc_flags |= IFC_GOT_PRST;
    LSQ_INFO("stateless reset reported");
}


static struct lsquic_conn_ctx *
ietf_full_conn_ci_get_ctx (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    return conn->ifc_conn_ctx;
}


static void
ietf_full_conn_ci_set_ctx (struct lsquic_conn *lconn, lsquic_conn_ctx_t *ctx)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    conn->ifc_conn_ctx = ctx;
}


static unsigned
ietf_full_conn_ci_n_pending_streams (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    return conn->ifc_n_delayed_streams;
}


static unsigned
ietf_full_conn_ci_n_avail_streams (const struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    return avail_streams_count(conn, !(conn->ifc_flags & IFC_SERVER), SD_BIDI);
}


static void
ietf_full_conn_ci_make_stream (struct lsquic_conn *lconn)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;

    if ((lconn->cn_flags & LSCONN_HANDSHAKE_DONE)
        && (conn->ifc_flags & (IFC_HTTP|IFC_HAVE_PEER_SET)) != IFC_HTTP
        && ietf_full_conn_ci_n_avail_streams(lconn) > 0)
    {
        if (0 != create_bidi_stream_out(conn))
            ABORT_ERROR("could not create new stream: %s", strerror(errno));
    }
    else if (either_side_going_away(conn))
    {
        (void) conn->ifc_stream_if->on_new_stream(conn->ifc_stream_ctx, NULL);
        LSQ_DEBUG("going away: no streams will be initiated");
    }
    else
    {
        ++conn->ifc_n_delayed_streams;
        LSQ_DEBUG("delayed stream creation.  Backlog size: %u",
                                                conn->ifc_n_delayed_streams);
    }
}


static void
ietf_full_conn_ci_internal_error (struct lsquic_conn *lconn,
                                                    const char *format, ...)
{
    struct ietf_full_conn *const conn = (struct ietf_full_conn *) lconn;
    LSQ_INFO("internal error reported");
    ABORT_QUIETLY(0, TEC_INTERNAL_ERROR, "Internal error");
}


static const struct conn_iface ietf_full_conn_iface = {
    .ci_can_write_ack        =  ietf_full_conn_ci_can_write_ack,
    .ci_cancel_pending_streams =  ietf_full_conn_ci_cancel_pending_streams,
    .ci_client_call_on_new   =  ietf_full_conn_ci_client_call_on_new,
    .ci_close                =  ietf_full_conn_ci_close,
    .ci_destroy              =  ietf_full_conn_ci_destroy,
    .ci_get_ctx              =  ietf_full_conn_ci_get_ctx,
    .ci_get_engine           =  NULL,   /* TODO */
    .ci_get_stream_by_id     =  NULL,   /* TODO */
    .ci_going_away           =  ietf_full_conn_ci_going_away,
    .ci_hsk_done             =  ietf_full_conn_ci_hsk_done,
    .ci_internal_error       =  ietf_full_conn_ci_internal_error,
    .ci_is_push_enabled      =  ietf_full_conn_ci_is_push_enabled,
    .ci_is_tickable          =  ietf_full_conn_ci_is_tickable,
    .ci_make_stream          =  ietf_full_conn_ci_make_stream,
    .ci_n_avail_streams      =  ietf_full_conn_ci_n_avail_streams,
    .ci_n_pending_streams    =  ietf_full_conn_ci_n_pending_streams,
    .ci_next_packet_to_send  =  ietf_full_conn_ci_next_packet_to_send,
    .ci_next_tick_time       =  ietf_full_conn_ci_next_tick_time,
    .ci_packet_in            =  ietf_full_conn_ci_packet_in,
    .ci_packet_not_sent      =  ietf_full_conn_ci_packet_not_sent,
    .ci_packet_sent          =  ietf_full_conn_ci_packet_sent,
    .ci_set_ctx              =  ietf_full_conn_ci_set_ctx,
    .ci_status               =  ietf_full_conn_ci_status,
    .ci_stateless_reset      =  ietf_full_conn_ci_stateless_reset,
    .ci_tick                 =  ietf_full_conn_ci_tick,
    .ci_write_ack            =  ietf_full_conn_ci_write_ack,
};

static const struct conn_iface *ietf_full_conn_iface_ptr =
                                                &ietf_full_conn_iface;


static void
on_priority (void *ctx, const struct hq_priority *priority)
{
    struct ietf_full_conn *const conn = ctx;
    LSQ_DEBUG("%s: %s #%"PRIu64" depends on %s #%"PRIu64"; "
        "exclusive: %d; weight: %u", __func__,
        lsquic_hqelt2str[priority->hqp_prio_type], priority->hqp_prio_id,
        lsquic_hqelt2str[priority->hqp_dep_type], priority->hqp_dep_id,
        priority->hqp_exclusive, HQP_WEIGHT(priority));
    /* TODO */
}


static void
on_cancel_push (void *ctx, uint64_t push_id)
{
    struct ietf_full_conn *const conn = ctx;
    LSQ_DEBUG("%s: %"PRIu64, __func__, push_id);
    /* TODO */
}


static void
on_max_push_id (void *ctx, uint64_t push_id)
{
    struct ietf_full_conn *const conn = ctx;
    LSQ_DEBUG("%s: %"PRIu64, __func__, push_id);
    /* TODO */
}


static void
on_settings_frame (void *ctx)
{
    struct ietf_full_conn *const conn = ctx;
    unsigned dyn_table_size, max_risked_streams;

    LSQ_DEBUG("SETTINGS frame");
    if (conn->ifc_flags & IFC_HAVE_PEER_SET)
    {
        ABORT_WARN("second incoming SETTING frame on HTTP control stream");
        return;
    }

    conn->ifc_flags |= IFC_HAVE_PEER_SET;
    dyn_table_size = MIN(conn->ifc_settings->es_qpack_enc_max_size,
                                conn->ifc_peer_hq_settings.header_table_size);
    max_risked_streams = MIN(conn->ifc_settings->es_qpack_enc_max_blocked,
                            conn->ifc_peer_hq_settings.qpack_blocked_streams);
    if (0 != lsquic_qeh_settings(&conn->ifc_qeh,
            conn->ifc_peer_hq_settings.header_table_size,
            dyn_table_size, max_risked_streams, conn->ifc_flags & IFC_SERVER))
        ABORT_WARN("could not initialize QPACK encoder handler");
    if (avail_streams_count(conn, conn->ifc_flags & IFC_SERVER, SD_UNI) > 0)
    {
        if (0 != create_qenc_stream_out(conn))
            ABORT_WARN("cannot create outgoing QPACK encoder stream");
    }
    else
        LSQ_DEBUG("cannot create QPACK encoder stream due to unidir limit");
    maybe_create_delayed_streams(conn);
}


static void
on_setting (void *ctx, uint16_t setting_id, uint64_t value)
{
    struct ietf_full_conn *const conn = ctx;

    switch (setting_id)
    {
    case HQSID_QPACK_BLOCKED_STREAMS:
        LSQ_DEBUG("Peer's SETTINGS_QPACK_BLOCKED_STREAMS=%"PRIu64, value);
        conn->ifc_peer_hq_settings.qpack_blocked_streams = value;
        break;
    case HQSID_NUM_PLACEHOLDERS:
        LSQ_DEBUG("Peer's SETTINGS_NUM_PLACEHOLDERS=%"PRIu64, value);
    conn->ifc_peer_hq_settings.num_placeholders
        = MIN(value, conn->ifc_settings->es_h3_placeholders);
    lsquic_prio_tree_set_ph(conn->ifc_pub.u.ietf.prio_tree,
                        conn->ifc_peer_hq_settings.num_placeholders);
        break;
    case HQSID_HEADER_TABLE_SIZE:
        LSQ_DEBUG("Peer's SETTINGS_HEADER_TABLE_SIZE=%"PRIu64, value);
        conn->ifc_peer_hq_settings.header_table_size = value;
        break;
    case HQSID_MAX_HEADER_LIST_SIZE:
        LSQ_DEBUG("Peer's SETTINGS_MAX_HEADER_LIST_SIZE=%"PRIu64, value);
        conn->ifc_peer_hq_settings.max_header_list_size = value;
        /* TODO: apply it */
        break;
    default:
        LSQ_DEBUG("received unknown SETTING 0x%"PRIX16"=0x%"PRIX64
                                        "; ignore it", setting_id, value);
        break;
    }
}


static void
on_goaway (void *ctx, uint64_t stream_id)
{
    struct ietf_full_conn *const conn = ctx;
    LSQ_DEBUG("%s: %"PRIu64, __func__, stream_id);
    /* TODO */
}


static void
on_unexpected_frame (void *ctx, enum hq_frame_type frame_type)
{
    struct ietf_full_conn *const conn = ctx;
    LSQ_DEBUG("%s: TODO", __func__);
    /* TODO */
}


static const struct hcsi_callbacks hcsi_callbacks =
{
    .on_priority            = on_priority,
    .on_cancel_push         = on_cancel_push,
    .on_max_push_id         = on_max_push_id,
    .on_settings_frame      = on_settings_frame,
    .on_setting             = on_setting,
    .on_goaway              = on_goaway,
    .on_unexpected_frame    = on_unexpected_frame,
};


static lsquic_stream_ctx_t *
hcsi_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct ietf_full_conn *const conn = (void *) stream_if_ctx;
    conn->ifc_stream_hcsi = stream;
    lsquic_hcsi_reader_init(&conn->ifc_hcsi.reader, &conn->ifc_conn,
                            &hcsi_callbacks, conn);
    lsquic_stream_wantread(stream, 1);
    return stream_if_ctx;
}


struct feed_hcsi_ctx
{
    struct ietf_full_conn *conn;
    int                    s;
};


static size_t
feed_hcsi_reader (void *ctx, const unsigned char *buf, size_t bufsz, int fin)
{
    struct feed_hcsi_ctx *feed_ctx = ctx;
    struct ietf_full_conn *conn = feed_ctx->conn;

    feed_ctx->s = lsquic_hcsi_reader_feed(&conn->ifc_hcsi.reader, buf, bufsz);
    return bufsz;
}


static void
hcsi_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct ietf_full_conn *const conn = (void *) ctx;
    struct feed_hcsi_ctx feed_ctx = { conn, 0, };
    ssize_t nread;

    nread = lsquic_stream_readf(stream, feed_hcsi_reader, &feed_ctx);
    LSQ_DEBUG("fed %zd bytes to HTTP control stream reader, status=%d",
        nread, feed_ctx.s);
    if (nread < 0)
    {
        lsquic_stream_wantread(stream, 0);
        ABORT_WARN("error reading from HTTP control stream");
    }
    else if (nread == 0)
    {
        lsquic_stream_wantread(stream, 0);
        ABORT_WARN("FIN on HTTP control stream");
    }
    else if (feed_ctx.s != 0)
    {
        lsquic_stream_wantread(stream, 0);
        ABORT_WARN("error processing HTTP control stream");
    }
}


static void
hcsi_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static void
hcsi_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct ietf_full_conn *const conn = (void *) ctx;
    conn->ifc_stream_hcsi = NULL;
}


static const struct lsquic_stream_if hcsi_if =
{
    .on_new_stream  = hcsi_on_new,
    .on_read        = hcsi_on_read,
    .on_write       = hcsi_on_write,
    .on_close       = hcsi_on_close,
};


static lsquic_stream_ctx_t *
unicla_on_new (void *stream_if_ctx, struct lsquic_stream *stream)
{
    lsquic_stream_wantread(stream, 1);
    return stream_if_ctx;
}


static void
unicla_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct ietf_full_conn *const conn = (void *) ctx;
    unsigned char type;
    ssize_t nr;

    nr = lsquic_stream_read(stream, &type, 1);
    LSQ_DEBUG("unistream classifier read %zd byte%.*s", nr, nr == 0, "s");
    if (nr > 0)
    {
        switch (type)
        {
        case HQUST_CONTROL:
            if (!conn->ifc_stream_hcsi)
            {
                LSQ_DEBUG("Incoming HTTP control stream ID: %"PRIu64,
                                                                stream->id);
                lsquic_stream_set_stream_if(stream, &hcsi_if, conn);
            }
            else
            {
                ABORT_WARN("Incoming HTTP control stream already exists");
                /* TODO: special error code? */
                lsquic_stream_close(stream);
            }
            break;
        case HQUST_QPACK_ENC:
            if (!lsquic_qdh_has_enc_stream(&conn->ifc_qdh))
            {
                LSQ_DEBUG("Incoming QPACK encoder stream ID: %"PRIu64,
                                                                stream->id);
                lsquic_stream_set_stream_if(stream, lsquic_qdh_enc_sm_in_if,
                                                                &conn->ifc_qdh);
            }
            else
            {
                ABORT_WARN("Incoming QPACK encoder stream already exists");
                /* TODO: special error code? */
                lsquic_stream_close(stream);
            }
            break;
        case HQUST_QPACK_DEC:
            if (!lsquic_qeh_has_dec_stream(&conn->ifc_qeh))
            {
                LSQ_DEBUG("Incoming QPACK decoder stream ID: %"PRIu64,
                                                                stream->id);
                lsquic_stream_set_stream_if(stream, lsquic_qeh_dec_sm_in_if,
                                                                &conn->ifc_qeh);
            }
            else
            {
                ABORT_WARN("Incoming QPACK decoder stream already exists");
                /* TODO: special error code? */
                lsquic_stream_close(stream);
            }
            break;
        case HQUST_PUSH:
            LSQ_WARN("TODO: push stream");
            break;
        default:
            LSQ_WARN("TODO: terminate unknown stream");
            break;
        }
    }
    else
    {
        if (nr < 0) /* This should never happen */
            LSQ_WARN("unicla: cannot read from stream %"PRIu64, stream->id);
        lsquic_stream_close(stream);
    }
}


static void
unicla_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    assert(0);
}


static void
unicla_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
}


static const struct lsquic_stream_if unicla_if =
{
    .on_new_stream  = unicla_on_new,
    .on_read        = unicla_on_read,
    .on_write       = unicla_on_write,
    .on_close       = unicla_on_close,
};


static const struct lsquic_stream_if *unicla_if_ptr = &unicla_if;

typedef char dcid_elem_fits_in_128_bytes[(sizeof(struct dcid_elem) <= 128) - 1];