/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_ENC_SESS_H
#define LSQUIC_ENC_SESS_H 1

struct lsquic_engine_public;
struct lsquic_packet_out;
struct lsquic_packet_in;
struct stream_wrapper;
struct ver_neg;
struct lsquic_conn;
struct transport_params;
struct lsquic_cid;
struct ssl_stream_method_st;
struct ssl_st;
struct sockaddr;
struct conn_cid_elem;

#define DNONC_LENGTH 32
#define SRST_LENGTH 16

/* From [draft-ietf-quic-tls-14]:
 *
 * Data is protected using a number of encryption levels:
 *
 * o  Plaintext
 *
 * o  Early Data (0-RTT) Keys
 *
 * o  Handshake Keys
 *
 * o  Application Data (1-RTT) Keys
 */

/* This enum maps to the list above */
enum enc_level
{
    ENC_LEV_CLEAR,
    ENC_LEV_EARLY,
    ENC_LEV_INIT,
    ENC_LEV_FORW,
    N_ENC_LEVS
};

enum handshake_error            /* TODO: rename this enum */
{
    DATA_NOT_ENOUGH = -2,
    DATA_FORMAT_ERROR = -1,
    HS_ERROR = -1,
    DATA_NO_ERROR = 0,
    HS_SHLO = 0,
    HS_1RTT = 1,
    HS_2RTT = 2,
};

#ifndef LSQUIC_KEEP_ENC_SESS_HISTORY
#   ifndef NDEBUG
#       define LSQUIC_KEEP_ENC_SESS_HISTORY 1
#   else
#       define LSQUIC_KEEP_ENC_SESS_HISTORY 0
#   endif
#endif

#if LSQUIC_KEEP_ENC_SESS_HISTORY
#define ESHIST_BITS 7
#define ESHIST_MASK ((1 << ESHIST_BITS) - 1)
#define ESHIST_STR_SIZE ((1 << ESHIST_BITS) + 1)
#endif

enum enc_packout { ENCPA_OK, ENCPA_NOMEM, ENCPA_BADCRYPT, };

enum dec_packin {
    DECPI_OK,
    DECPI_NOMEM,
    DECPI_TOO_SHORT,
    DECPI_NOT_YET,
    DECPI_BADCRYPT,
    DECPI_VIOLATION,
};

typedef void enc_session_t;

struct enc_session_funcs_common
{
    /* Global initialization: call once per implementation */
    int (*esf_global_init)(int flags);

    /* Global cleanup: call once per implementation */
    void (*esf_global_cleanup) (void);

    enum enc_packout
    (*esf_encrypt_packet) (enc_session_t *, const struct lsquic_engine_public *,
        const struct lsquic_conn *, struct lsquic_packet_out *);

    enum dec_packin
    (*esf_decrypt_packet)(enc_session_t *, struct lsquic_engine_public *,
        const struct lsquic_conn *, struct lsquic_packet_in *);

    struct stack_st_X509 *
    (*esf_get_server_cert_chain) (enc_session_t *);

    int
    (*esf_verify_reset_token) (enc_session_t *, const unsigned char *, size_t);

    int
    (*esf_did_zero_rtt_succeed) (enc_session_t *);

    int
    (*esf_is_zero_rtt_enabled) (enc_session_t *);

    unsigned
    esf_tag_len;
};

struct enc_session_funcs_gquic
{
#if LSQUIC_KEEP_ENC_SESS_HISTORY
    /* Grab encryption session history */
    void (*esf_get_hist) (enc_session_t *,
                                            char buf[ESHIST_STR_SIZE]);
#endif

    /* Destroy enc session */
    void (*esf_destroy)(enc_session_t *enc_session);

    /* Return true if handshake has been completed */
    int (*esf_is_hsk_done)(enc_session_t *enc_session);

    /* Get value of setting specified by `tag' */
    int (*esf_get_peer_setting) (enc_session_t *, uint32_t tag,
                                                                uint32_t *val);

    /* Get value of peer option (that from COPT array) */
    int (*esf_get_peer_option) (enc_session_t *enc_session,
                                                                uint32_t tag);

    /* Create client session */
    enc_session_t *
    (*esf_create_client) (const char *domain, lsquic_cid_t cid,
                                    const struct lsquic_engine_public *,
                                    const unsigned char *, size_t);

    /* Generate connection ID */
    lsquic_cid_t (*esf_generate_cid) (void);

    /* -1 error, 0, OK, response in `buf' */
    int
    (*esf_gen_chlo) (enc_session_t *, enum lsquic_version,
                                                uint8_t *buf, size_t *len);

    int
    (*esf_handle_chlo_reply) (enc_session_t *,
                                                const uint8_t *data, int len);

    size_t
    (*esf_mem_used)(enc_session_t *);

    /* Zero-rtt serialization needs the knowledge of the QUIC version, that's
     * why there is a separate method for thus.  Plus, we want to be able to
     * call it after the "handshake is done" callback is called.
     */
    void (*esf_maybe_dispatch_zero_rtt) (enc_session_t *,
            struct lsquic_conn *conn,
            void (*cb)(struct lsquic_conn *, const unsigned char *, size_t));
};

enum iquic_handshake_status {
    IHS_WANT_READ,
    IHS_WANT_WRITE,
    IHS_STOP,
};

struct crypto_stream_if
{
    ssize_t     (*csi_write) (void *stream, const void *buf, size_t len);
    int         (*csi_flush) (void *stream);
    ssize_t     (*csi_readf) (void *stream,
        size_t (*readf)(void *, const unsigned char *, size_t, int), void *ctx);
    int         (*csi_wantwrite) (void *stream, int is_want);
    int         (*csi_wantread) (void *stream, int is_want);
    enum enc_level
                (*csi_enc_level) (void *stream);
};

struct enc_session_funcs_iquic
{
    struct conn_cid_elem *
    (*esfi_add_scid) (const struct lsquic_engine_public *,
                                                    struct lsquic_conn *);

    enc_session_t *
    (*esfi_create_client) (const char *domain, struct lsquic_engine_public *,
                           struct lsquic_conn *, const struct ver_neg *,
                           void *(crypto_streams)[4],
                           const struct crypto_stream_if *,
                           const unsigned char *, size_t);

    void
    (*esfi_destroy) (enc_session_t *);

    struct ssl_st *
    (*esfi_get_ssl) (enc_session_t *);

    int
    (*esfi_get_peer_transport_params) (enc_session_t *,
                                                struct transport_params *);

    int
    (*esfi_reset_dcid) (enc_session_t *, const struct lsquic_cid *);

};

extern
#ifdef NDEBUG
const
#endif
struct enc_session_funcs_common lsquic_enc_session_common_gquic_1;
extern const struct enc_session_funcs_common lsquic_enc_session_common_id20;

extern
#ifdef NDEBUG
const
#endif
struct enc_session_funcs_gquic lsquic_enc_session_gquic_gquic_1;

extern const struct enc_session_funcs_iquic lsquic_enc_session_iquic_id20;

#define select_esf_common_by_ver(ver) ( \
    ver == LSQVER_ID20 ? &lsquic_enc_session_common_id20 : \
    ver == LSQVER_VERNEG ? &lsquic_enc_session_common_id20 : \
    &lsquic_enc_session_common_gquic_1 )

#define select_esf_gquic_by_ver(ver) ( \
    ver ? &lsquic_enc_session_gquic_gquic_1 : &lsquic_enc_session_gquic_gquic_1)

#define select_esf_iquic_by_ver(ver) ( \
    ver ? &lsquic_enc_session_iquic_id20 : &lsquic_enc_session_iquic_id20)

extern const char *const lsquic_enclev2str[];

extern const struct lsquic_stream_if lsquic_cry_sm_if;

/* RFC 7301, Section 3.2 */
#define ALERT_NO_APPLICATION_PROTOCOL 120

enum lsquic_version
lsquic_zero_rtt_version (const unsigned char *, size_t);

#endif
