/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_enc_sess_ietf.c -- Crypto session for IETF QUIC
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <openssl/chacha.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "lsquic_types.h"
#include "lsquic_hkdf.h"
#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_sizes.h"
#include "lsquic_hash.h"
#include "lsquic_conn.h"
#include "lsquic_enc_sess.h"
#include "lsquic_parse.h"
#include "lsquic_mm.h"
#include "lsquic_engine_public.h"
#include "lsquic_packet_common.h"
#include "lsquic_packet_out.h"
#include "lsquic_packet_in.h"
#include "lsquic_util.h"
#include "lsquic_byteswap.h"
#include "lsquic_ev_log.h"
#include "lsquic_trans_params.h"
#include "lsquic_engine_public.h"
#include "lsquic_version.h"
#include "lsquic_ver_neg.h"
#include "lsquic_byteswap.h"
#include "lsquic_frab_list.h"

#if __GNUC__
#   define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#   define UNLIKELY(cond) cond
#endif

#define LSQUIC_LOGGER_MODULE LSQLM_HANDSHAKE
#define LSQUIC_LOG_CONN_ID lsquic_conn_log_cid(enc_sess->esi_conn)
#include "lsquic_logger.h"

/* [draft-ietf-quic-tls-11] Section 5.3.2 */
#define HSK_SECRET_SZ SHA256_DIGEST_LENGTH

/* TODO: Specify ciphers */
#define HSK_CIPHERS "TLS13-AES-128-GCM-SHA256"  \
                   ":TLS13-AES-256-GCM-SHA384"  \
                   ":TLS13-CHACHA20-POLY1305-SHA256"

#define KEY_LABEL "quic key"
#define KEY_LABEL_SZ (sizeof(KEY_LABEL) - 1)
#define IV_LABEL "quic iv"
#define IV_LABEL_SZ (sizeof(IV_LABEL) - 1)
#define PN_LABEL "quic hp"
#define PN_LABEL_SZ (sizeof(PN_LABEL) - 1)

/* This is seems to be true for all of the ciphers used by IETF QUIC.
 * XXX: Perhaps add a check?
 */
#define IQUIC_TAG_LEN 16

static const struct alpn_map {
    enum lsquic_version  version;
    const unsigned char *alpn;
} s_alpns[] = {
    {   LSQVER_ID20, (unsigned char *) "\x05h3-20",     },
    {   LSQVER_VERNEG, (unsigned char *) "\x05h3-20",     },
};

struct enc_sess_iquic;
struct crypto_ctx;
struct crypto_ctx_pair;

static const int s_log_seal_and_open;
static char s_str[0x1000];

static const SSL_QUIC_METHOD cry_quic_method;

static int s_idx = -1;

static int
setup_handshake_keys (struct enc_sess_iquic *, const lsquic_cid_t *);

static struct stack_st_X509 *
iquic_esf_get_server_cert_chain (enc_session_t *);


typedef void (*gen_hp_mask_f)(struct enc_sess_iquic *,
    const struct crypto_ctx *, const struct crypto_ctx_pair *,
    const unsigned char *sample, unsigned char mask[16]);

struct crypto_ctx
{
    EVP_AEAD_CTX        yk_aead_ctx;
    unsigned            yk_key_sz;
    unsigned            yk_iv_sz;
    unsigned            yk_hp_sz;
    enum {
        YK_INITED = 1 << 0,
    }                   yk_flags;
    unsigned char       yk_key_buf[EVP_MAX_KEY_LENGTH];
    unsigned char       yk_iv_buf[EVP_MAX_IV_LENGTH];
    unsigned char       yk_hp_buf[EVP_MAX_KEY_LENGTH];
};


struct crypto_ctx_pair
{
    lsquic_packno_t     ykp_thresh;
    enum enc_level      ykp_enc_level;
    const EVP_CIPHER   *ykp_hp;
    gen_hp_mask_f       ykp_gen_hp_mask;
    struct crypto_ctx   ykp_ctx[2]; /* client, server */
};


/* [draft-ietf-quic-tls-12] Section 5.3.6 */
static int
init_crypto_ctx (struct crypto_ctx *crypto_ctx, const EVP_MD *md,
                 const EVP_AEAD *aead, const unsigned char *secret,
                 size_t secret_sz, enum evp_aead_direction_t dir)
{
    crypto_ctx->yk_key_sz = EVP_AEAD_key_length(aead);
    crypto_ctx->yk_iv_sz = EVP_AEAD_nonce_length(aead);
    crypto_ctx->yk_hp_sz = EVP_AEAD_key_length(aead);

    if (crypto_ctx->yk_key_sz > sizeof(crypto_ctx->yk_key_buf)
        || crypto_ctx->yk_iv_sz > sizeof(crypto_ctx->yk_iv_buf))
    {
        return -1;
    }

    lsquic_qhkdf_expand(md, secret, secret_sz, KEY_LABEL, KEY_LABEL_SZ,
        crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz);
    lsquic_qhkdf_expand(md, secret, secret_sz, IV_LABEL, IV_LABEL_SZ,
        crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
    lsquic_qhkdf_expand(md, secret, secret_sz, PN_LABEL, PN_LABEL_SZ,
        crypto_ctx->yk_hp_buf, crypto_ctx->yk_hp_sz);
    if (!EVP_AEAD_CTX_init_with_direction(&crypto_ctx->yk_aead_ctx, aead,
            crypto_ctx->yk_key_buf, crypto_ctx->yk_key_sz, IQUIC_TAG_LEN, dir))
        return -1;

    crypto_ctx->yk_flags |= YK_INITED;

    return 0;
}


static void
cleanup_crypto_ctx (struct crypto_ctx *crypto_ctx)
{
    if (crypto_ctx->yk_flags & YK_INITED)
    {
        EVP_AEAD_CTX_cleanup(&crypto_ctx->yk_aead_ctx);
        crypto_ctx->yk_flags &= ~YK_INITED;
    }
}


struct enc_sess_iquic
{
    struct lsquic_engine_public
                        *esi_enpub;
    struct lsquic_conn  *esi_conn;
    void               **esi_streams;
    const struct crypto_stream_if *esi_cryst_if;
    const struct ver_neg
                        *esi_ver_neg;
    SSL                 *esi_ssl;

    struct crypto_ctx_pair *
                         esi_crypto_pair[N_ENC_LEVS + 1];
    lsquic_packno_t      esi_max_packno[N_PNS];
    lsquic_cid_t         esi_odcid;
    enum {
        ESI_INITIALIZED  = 1 << 0,
        ESI_LOG_SECRETS  = 1 << 1,
        ESI_HANDSHAKE_OK = 1 << 2,
        ESI_ODCID        = 1 << 3,
        ESI_ON_WRITE     = 1 << 4,
        ESI_USE_SSL_TICKET = 1 << 7,
    }                    esi_flags;
    enum evp_aead_direction_t
                         esi_dir[2];        /* client, server */
    enum enc_level       esi_last_w;
    char                *esi_hostname;
    void                *esi_keylog_handle;
    const unsigned char *esi_alpn;
    unsigned char       *esi_zero_rtt_buf;
    size_t               esi_zero_rtt_sz;
    /* We never use the first two levels, so it seems we could reduce the
     * memory requirement here at the cost of adding some code.
     */
    struct frab_list     esi_frals[N_ENC_LEVS];
};


static void
gen_hp_mask_aes (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *sample, unsigned char mask[EVP_MAX_BLOCK_LENGTH])
{
    EVP_CIPHER_CTX hp_ctx;
    int out_len;

    EVP_CIPHER_CTX_init(&hp_ctx);
    if (EVP_EncryptInit_ex(&hp_ctx, pair->ykp_hp, NULL,
                                crypto_ctx->yk_hp_buf, 0)
        && EVP_EncryptUpdate(&hp_ctx, mask, &out_len, sample, 16))
    {
        assert(out_len >= 5);
    }
    else
    {
        LSQ_WARN("cannot generate hp mask, error code: %"PRIu32,
                                                            ERR_get_error());
        enc_sess->esi_conn->cn_if->ci_internal_error(enc_sess->esi_conn,
            "cannot generate hp mask, error code: %"PRIu32, ERR_get_error());
    }

    (void) EVP_CIPHER_CTX_cleanup(&hp_ctx);
}


static void
gen_hp_mask_chacha20 (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *sample, unsigned char mask[EVP_MAX_BLOCK_LENGTH])
{
    const uint8_t *nonce;
    uint32_t counter;

#if __BYTE_ORDER == __LITTLE_ENDIAN
    memcpy(&counter, sample, sizeof(counter));
#else
#error TODO: support non-little-endian machines
#endif
    nonce = sample + sizeof(counter);
    CRYPTO_chacha_20(mask, (unsigned char [5]) { 0, 0, 0, 0, 0, }, 5,
                                        crypto_ctx->yk_hp_buf, nonce, counter);
}


static void
apply_hp (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        unsigned char *dst, unsigned packno_off, unsigned packno_len)
{
    unsigned char mask[EVP_MAX_BLOCK_LENGTH];
    char mask_str[5 * 2 + 1];

    pair->ykp_gen_hp_mask(enc_sess, crypto_ctx, pair,
                                                dst + packno_off + 4, mask);
    LSQ_DEBUG("apply header protection using mask %s",
                                                HEXSTR(mask, 5, mask_str));
    dst[0] ^= (0xF | (((dst[0] & 0x80) == 0) << 4)) & mask[0];
    switch (packno_len)
    {
    case 4:
        dst[packno_off + 3] ^= mask[4];
        /* fall-through */
    case 3:
        dst[packno_off + 2] ^= mask[3];
        /* fall-through */
    case 2:
        dst[packno_off + 1] ^= mask[2];
        /* fall-through */
    default:
        dst[packno_off + 0] ^= mask[1];
    }
}


static lsquic_packno_t
decode_packno (lsquic_packno_t max_packno, lsquic_packno_t packno,
                                                                unsigned shift)
{
    lsquic_packno_t candidates[3], epoch_delta;
    int64_t diffs[3];
    unsigned min;;

    epoch_delta = 1ULL << shift;
    candidates[1] = (max_packno & ~(epoch_delta - 1)) + packno;
    candidates[0] = candidates[1] - epoch_delta;
    candidates[2] = candidates[1] + epoch_delta;

    diffs[0] = llabs((int64_t) candidates[0] - (int64_t) max_packno);
    diffs[1] = llabs((int64_t) candidates[1] - (int64_t) max_packno);
    diffs[2] = llabs((int64_t) candidates[2] - (int64_t) max_packno);

    min = diffs[1] < diffs[0];
    if (diffs[2] < diffs[min])
        min = 2;

    return candidates[min];
}


static lsquic_packno_t
strip_hp (struct enc_sess_iquic *enc_sess,
        const struct crypto_ctx *crypto_ctx, const struct crypto_ctx_pair *pair,
        const unsigned char *iv, unsigned char *dst, unsigned packno_off,
        unsigned *packno_len)
{
    enum packnum_space pns;
    lsquic_packno_t packno;
    unsigned shift;
    unsigned char mask[EVP_MAX_BLOCK_LENGTH];
    char mask_str[5 * 2 + 1];

    pair->ykp_gen_hp_mask(enc_sess, crypto_ctx, pair, iv, mask);
    LSQ_DEBUG("strip header protection using mask %s",
                                                HEXSTR(mask, 5, mask_str));
    dst[0] ^= (0xF | (((dst[0] & 0x80) == 0) << 4)) & mask[0];
    packno = 0;
    shift = 0;
    *packno_len = 1 + (dst[0] & 3);
    switch (*packno_len)
    {
    case 4:
        dst[packno_off + 3] ^= mask[4];
        packno |= dst[packno_off + 3];
        shift += 8;
        /* fall-through */
    case 3:
        dst[packno_off + 2] ^= mask[3];
        packno |= dst[packno_off + 2] << shift;
        shift += 8;
        /* fall-through */
    case 2:
        dst[packno_off + 1] ^= mask[2];
        packno |= dst[packno_off + 1] << shift;
        shift += 8;
        /* fall-through */
    default:
        dst[packno_off + 0] ^= mask[1];
        packno |= dst[packno_off + 0] << shift;
        shift += 8;
    }
    pns = lsquic_enclev2pns[pair->ykp_enc_level];
    return decode_packno(enc_sess->esi_max_packno[pns], packno, shift);
}


static int
gen_trans_params (struct enc_sess_iquic *enc_sess, unsigned char *buf,
                                                                size_t bufsz)
{
    const struct lsquic_engine_settings *const settings =
                                    &enc_sess->esi_enpub->enp_settings;
    struct transport_params params;
    int len;

    memset(&params, 0, sizeof(params));
    params.tp_init_max_data = settings->es_init_max_data;
    params.tp_init_max_stream_data_bidi_local
                            = settings->es_init_max_stream_data_bidi_local;
    params.tp_init_max_stream_data_bidi_remote
                            = settings->es_init_max_stream_data_bidi_remote;
    params.tp_init_max_stream_data_uni
                            = settings->es_init_max_stream_data_uni;
    params.tp_init_max_streams_uni
                            = settings->es_init_max_streams_uni;
    params.tp_init_max_streams_bidi
                            = settings->es_init_max_streams_bidi;
    params.tp_ack_delay_exponent
                            = TP_DEF_ACK_DELAY_EXP;
    params.tp_idle_timeout  = settings->es_idle_timeout * 1000;
    params.tp_max_ack_delay = TP_DEF_MAX_ACK_DELAY;
    params.tp_max_packet_size = 1370 /* XXX: based on socket */;

    len = lsquic_tp_encode(&params, buf, bufsz);
    if (len >= 0)
        LSQ_DEBUG("generated transport parameters buffer of %d bytes", len);
    else
        LSQ_WARN("cannot generate transport parameters: %d", errno);
    return len;
}


static void
generate_cid (lsquic_cid_t *cid, int len)
{
    if (!len)
        /* If not set, generate ID between 8 and MAX_CID_LEN bytes in length */
        len = 8 + rand() % (MAX_CID_LEN - 7);
    RAND_bytes(cid->idbuf, len);
    cid->len = len;
}


/*
 * Format:
 *      uint32_t    lsquic_ver_tag_t
 *      uint32_t    encoder version
 *      uint32_t    ticket_size
 *      uint8_t     ticket_buf[ ticket_size ]
 *      uint32_t    trapa_size
 *      uint8_t     trapa_buf[ trapa_size ]
 */

#define ZERO_RTT_VERSION 1

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define READ_NUM(var_, ptr_) do {                               \
    memcpy(&var_, ptr_, sizeof(var_));                          \
    var_ = bswap_32(var_);                                      \
    ptr_ += sizeof(var_);                                       \
} while (0)
#else
#define READ_NUM(var_, ptr_) do {                               \
    memcpy(&var_, ptr_, sizeof(var_));                          \
    ptr_ += sizeof(var_);                                       \
} while (0)
#endif

static SSL_SESSION *
maybe_create_SSL_SESSION (struct enc_sess_iquic *enc_sess,
                                                    const SSL_CTX *ssl_ctx)
{
    SSL_SESSION *ssl_session;
    lsquic_ver_tag_t ver_tag;
    enum lsquic_version quic_ver;
    uint32_t rtt_ver, ticket_sz, trapa_sz;
    const unsigned char *ticket_buf, *trapa_buf, *p;
    const unsigned char *const end
                    = enc_sess->esi_zero_rtt_buf + enc_sess->esi_zero_rtt_sz;

    if (enc_sess->esi_zero_rtt_sz
                    < sizeof(ver_tag) + sizeof(rtt_ver) + sizeof(ticket_sz))
    {
        LSQ_DEBUG("rtt buf too short");
        return NULL;
    }

    p = enc_sess->esi_zero_rtt_buf;
    memcpy(&ver_tag, p, sizeof(ver_tag));
    p += sizeof(ver_tag);
    quic_ver = lsquic_tag2ver(ver_tag);
    if (quic_ver != enc_sess->esi_ver_neg->vn_ver)
    {
        LSQ_DEBUG("negotiated version %s does not match that in the zero-rtt "
            "info buffer", lsquic_ver2str[enc_sess->esi_ver_neg->vn_ver]);
        return NULL;
    }

    READ_NUM(rtt_ver, p);
    if (rtt_ver != ZERO_RTT_VERSION)
    {
        LSQ_DEBUG("cannot use zero-rtt buffer: encoded using %"PRIu32", "
                "while current version is %u", rtt_ver, ZERO_RTT_VERSION);
        return NULL;
    }

    READ_NUM(ticket_sz, p);
    if (p + ticket_sz > end)
    {
        LSQ_WARN("truncated ticket buffer");
        return NULL;
    }

    ticket_buf = p;
    p += ticket_sz;

    if (p + sizeof(trapa_sz) > end)
    {
        LSQ_WARN("too short to read trapa size");
        return NULL;
    }

    READ_NUM(trapa_sz, p);
    if (p + trapa_sz > end)
    {
        LSQ_WARN("truncated trapa buffer");
        return NULL;
    }
    trapa_buf = p;
    p += trapa_sz;
    assert(p == end);

    (void) /* TODO */ trapa_buf;

    ssl_session = SSL_SESSION_from_bytes(ticket_buf, ticket_sz, ssl_ctx);
    if (!ssl_session)
    {
        LSQ_WARN("SSL_SESSION could not be parsed out");
        return NULL;
    }

    LSQ_INFO("instantiated SSL_SESSION from serialized buffer");
    return ssl_session;
}


static void
init_frals (struct enc_sess_iquic *enc_sess)
{
    struct frab_list *fral;

    for (fral = enc_sess->esi_frals; fral < enc_sess->esi_frals
            + sizeof(enc_sess->esi_frals) / sizeof(enc_sess->esi_frals[0]);
                ++fral)
        lsquic_frab_list_init(fral, 0x100, NULL, NULL, NULL);
}


static enc_session_t *
iquic_esfi_create_client (const char *hostname,
            struct lsquic_engine_public *enpub, struct lsquic_conn *lconn,
            const struct ver_neg *ver_neg, void *crypto_streams[4],
            const struct crypto_stream_if *cryst_if,
            const unsigned char *zero_rtt, size_t zero_rtt_sz)
{
    struct enc_sess_iquic *enc_sess;

    enc_sess = calloc(1, sizeof(*enc_sess));
    if (!enc_sess)
        return NULL;

    if (hostname)
    {
        enc_sess->esi_hostname = strdup(hostname);
        if (!enc_sess->esi_hostname)
        {
            free(enc_sess);
            return NULL;
        }
    }
    else
        enc_sess->esi_hostname = NULL;

    enc_sess->esi_enpub = enpub;
    enc_sess->esi_streams = crypto_streams;
    enc_sess->esi_cryst_if = cryst_if;
    enc_sess->esi_conn = lconn;
    enc_sess->esi_ver_neg = ver_neg;
    generate_cid(&lconn->cn_dcid, 0);

    enc_sess->esi_dir[0] = evp_aead_seal;
    enc_sess->esi_dir[1] = evp_aead_open;

    LSQ_DEBUGC("created client, DCID: %"CID_FMT, CID_BITS(&lconn->cn_dcid));
    {
        const char *log;
        log = getenv("LSQUIC_LOG_SECRETS");
        if (log)
        {
            if (atoi(log))
                enc_sess->esi_flags |= ESI_LOG_SECRETS;
            LSQ_DEBUG("will %slog secrets", atoi(log) ? "" : "not ");
        }
    }

    init_frals(enc_sess);

    if (0 != setup_handshake_keys(enc_sess, &lconn->cn_dcid))
    {
        free(enc_sess);
        return NULL;
    }

    /* Have to wait until the call to init_client() -- this is when the
     * result of version negotiation is known.
     */
    if (zero_rtt && zero_rtt_sz)
    {
        enc_sess->esi_zero_rtt_buf = malloc(zero_rtt_sz);
        if (enc_sess->esi_zero_rtt_buf)
        {
            memcpy(enc_sess->esi_zero_rtt_buf, zero_rtt, zero_rtt_sz);
            enc_sess->esi_zero_rtt_sz = zero_rtt_sz;
        }
        else
            enc_sess->esi_zero_rtt_sz = 0;
    }
    else
    {
        enc_sess->esi_zero_rtt_buf = NULL;
        enc_sess->esi_zero_rtt_sz = 0;
    }

    return enc_sess;
}


static void
log_crypto_pair (const struct enc_sess_iquic *enc_sess,
                    const struct crypto_ctx_pair *pair, const char *name)
{
    char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];
    LSQ_DEBUG("client %s key: %s", name,
        HEXSTR(pair->ykp_ctx[0].yk_key_buf, pair->ykp_ctx[0].yk_key_sz,
                                                                hexbuf));
    LSQ_DEBUG("client %s iv: %s", name,
        HEXSTR(pair->ykp_ctx[0].yk_iv_buf, pair->ykp_ctx[0].yk_iv_sz,
                                                                hexbuf));
    LSQ_DEBUG("client %s hp: %s", name,
        HEXSTR(pair->ykp_ctx[0].yk_hp_buf, pair->ykp_ctx[0].yk_hp_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s key: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_key_buf, pair->ykp_ctx[1].yk_key_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s iv: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_iv_buf, pair->ykp_ctx[1].yk_iv_sz,
                                                                hexbuf));
    LSQ_DEBUG("server %s hp: %s", name,
        HEXSTR(pair->ykp_ctx[1].yk_hp_buf, pair->ykp_ctx[1].yk_hp_sz,
                                                                hexbuf));
}


/* [draft-ietf-quic-tls-12] Section 5.3.2 */
static int
setup_handshake_keys (struct enc_sess_iquic *enc_sess, const lsquic_cid_t *cid)
{
    const EVP_MD *const md = EVP_sha256();
    const EVP_AEAD *const aead = EVP_aead_aes_128_gcm();
    struct crypto_ctx_pair *pair;
    size_t hsk_secret_sz;
    unsigned char hsk_secret[EVP_MAX_MD_SIZE];
    unsigned char secret[2][SHA256_DIGEST_LENGTH];  /* client, server */
    char hexbuf[EVP_MAX_MD_SIZE * 2 + 1];

    pair = calloc(1, sizeof(*pair));
    if (!pair)
        return -1;

    HKDF_extract(hsk_secret, &hsk_secret_sz, md, cid->idbuf, cid->len,
                                                        HSK_SALT, HSK_SALT_SZ);
    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
    {
        LSQ_DEBUG("handshake salt: %s", HEXSTR(HSK_SALT, HSK_SALT_SZ, hexbuf));
        LSQ_DEBUG("handshake secret: %s", HEXSTR(hsk_secret, hsk_secret_sz,
                                                                    hexbuf));
    }

    lsquic_qhkdf_expand(md, hsk_secret, hsk_secret_sz, CLIENT_LABEL,
                CLIENT_LABEL_SZ, secret[0], sizeof(secret[0]));
    LSQ_DEBUG("client handshake secret: %s",
        HEXSTR(secret[0], sizeof(secret[0]), hexbuf));
    if (0 != init_crypto_ctx(&pair->ykp_ctx[0], md, aead, secret[0],
                sizeof(secret[0]), enc_sess->esi_dir[0]))
        goto err;
    lsquic_qhkdf_expand(md, hsk_secret, hsk_secret_sz, SERVER_LABEL,
                SERVER_LABEL_SZ, secret[1], sizeof(secret[1]));
    LSQ_DEBUG("server handshake secret: %s",
        HEXSTR(secret[1], sizeof(secret[1]), hexbuf));
    if (0 != init_crypto_ctx(&pair->ykp_ctx[1], md, aead, secret[1],
                sizeof(secret[1]), enc_sess->esi_dir[1]))
        goto err;

    /* [draft-ietf-quic-tls-12] Section 5.6.1: AEAD_AES_128_GCM implies
     * 128-bit AES-CTR.
     */
    pair->ykp_hp = EVP_aes_128_ecb();
    pair->ykp_gen_hp_mask = gen_hp_mask_aes;

    pair->ykp_enc_level = ENC_LEV_CLEAR;
    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
        log_crypto_pair(enc_sess, pair, "handshake");
    enc_sess->esi_crypto_pair[ENC_LEV_CLEAR] = pair;

    return 0;

  err:
    cleanup_crypto_ctx(&pair->ykp_ctx[0]);
    cleanup_crypto_ctx(&pair->ykp_ctx[1]);
    free(pair);
    return -1;
}


static void
keylog_callback (const SSL *ssl, const char *line)
{
    struct enc_sess_iquic *enc_sess;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (enc_sess->esi_keylog_handle)
        enc_sess->esi_enpub->enp_kli->kli_log_line(
                                        enc_sess->esi_keylog_handle, line);
}


static void
maybe_setup_key_logging (struct enc_sess_iquic *enc_sess)
{
    if (enc_sess->esi_enpub->enp_kli)
    {
        enc_sess->esi_keylog_handle = enc_sess->esi_enpub->enp_kli->kli_open(
                        enc_sess->esi_enpub->enp_kli_ctx, enc_sess->esi_conn);
        LSQ_DEBUG("SSL keys %s be logged",
                            enc_sess->esi_keylog_handle ? "will" : "will not");
    }
}


static enum ssl_verify_result_t
verify_server_cert_callback (SSL *ssl, uint8_t *out_alert)
{
    struct enc_sess_iquic *enc_sess;
    struct stack_st_X509 *chain;
    int s;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    chain = SSL_get_peer_cert_chain(ssl);
    if (!chain)
    {
        LSQ_ERROR("cannot get peer chain");
        return ssl_verify_invalid;
    }

    s = enc_sess->esi_enpub->enp_verify_cert(
                                enc_sess->esi_enpub->enp_verify_ctx, chain);
    return s == 0 ? ssl_verify_ok : ssl_verify_invalid;
}


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define WRITE_NUM(var_, val_, ptr_) do {                        \
    var_ = (val_);                                              \
    var_ = bswap_32(var_);                                      \
    memcpy((ptr_), &var_, sizeof(var_));                        \
    ptr_ += sizeof(var_);                                       \
} while (0)
#else
#define WRITE_NUM(var_, val_, ptr_) do {                        \
    var_ = (val_);                                              \
    memcpy((ptr_), &var_, sizeof(var_));                        \
    ptr_ += sizeof(var_);                                       \
} while (0)
#endif

static int
iquic_new_session_cb (SSL *ssl, SSL_SESSION *session)
{
    struct enc_sess_iquic *enc_sess;
    uint32_t max_early_data_size, num;
    unsigned char *p, *buf;
    uint8_t *ticket_buf;
    size_t ticket_sz;
    lsquic_ver_tag_t tag;
    const uint8_t *trapa_buf;
    size_t trapa_sz, buf_sz;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    assert(enc_sess->esi_enpub->enp_stream_if->on_zero_rtt_info);

    max_early_data_size = SSL_SESSION_get_max_early_data_size(session);
    if (0xFFFFFFFFu != max_early_data_size)
        LSQ_WARN("max_early_data_size=0x%X, protocol violation",
                                                        max_early_data_size);

    SSL_get_peer_quic_transport_params(enc_sess->esi_ssl, &trapa_buf,
                                                                &trapa_sz);
    if (!(trapa_buf + trapa_sz))
    {
        LSQ_WARN("no transport parameters: cannot generate zero-rtt info");
        return 0;
    }
    if (trapa_sz > UINT32_MAX)
    {
        LSQ_WARN("trapa size too large: %zu", trapa_sz);
        return 0;
    }

    if (!SSL_SESSION_to_bytes(session, &ticket_buf, &ticket_sz))
    {
        LSQ_INFO("could not serialize new session");
        return 0;
    }
    if (ticket_sz > UINT32_MAX)
    {
        LSQ_WARN("ticket size too large: %zu", ticket_sz);
        OPENSSL_free(ticket_buf);
        return 0;
    }

    buf_sz = sizeof(tag) + sizeof(uint32_t) + sizeof(uint32_t)
                                + ticket_sz + sizeof(uint32_t) + trapa_sz;
    buf = malloc(buf_sz);
    if (!buf)
    {
        OPENSSL_free(ticket_buf);
        LSQ_WARN("%s: malloc failed", __func__);
        return 0;
    }

    p = buf;
    tag = lsquic_ver2tag(enc_sess->esi_conn->cn_version);
    memcpy(p, &tag, sizeof(tag));
    p += sizeof(tag);

    WRITE_NUM(num, ZERO_RTT_VERSION, p);
    WRITE_NUM(num, ticket_sz, p);
    memcpy(p, ticket_buf, ticket_sz);
    p += ticket_sz;
    WRITE_NUM(num, trapa_sz, p);
    memcpy(p, trapa_buf, trapa_sz);
    p += trapa_sz;

    assert(buf + buf_sz == p);
    OPENSSL_free(ticket_buf);

    LSQ_DEBUG("generated %zu bytes of zero-rtt buffer", buf_sz);

    enc_sess->esi_enpub->enp_stream_if->on_zero_rtt_info(enc_sess->esi_conn,
                                                                buf, buf_sz);
    free(buf);
    return 0;
}


static int
init_client (struct enc_sess_iquic *const enc_sess)
{
    SSL_CTX *ssl_ctx;
    SSL_SESSION *ssl_session;
    const struct alpn_map *am;
    int transpa_len;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];
#define hexbuf errbuf   /* This is a dual-purpose buffer */
    unsigned char trans_params[0x80];

    for (am = s_alpns; am < s_alpns + sizeof(s_alpns)
                                                / sizeof(s_alpns[0]); ++am)
        if (am->version == enc_sess->esi_ver_neg->vn_ver)
            goto ok;

    LSQ_ERROR("version %s has no matching ALPN",
                            lsquic_ver2str[enc_sess->esi_ver_neg->vn_ver]);
    return -1;

  ok:
    enc_sess->esi_alpn = am->alpn;
    ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx)
    {
        LSQ_ERROR("cannot create SSL context: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(ssl_ctx);
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT);
    if (enc_sess->esi_enpub->enp_stream_if->on_zero_rtt_info)
        SSL_CTX_sess_set_new_cb(ssl_ctx, iquic_new_session_cb);
    if (enc_sess->esi_enpub->enp_kli)
        SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
    if (enc_sess->esi_enpub->enp_verify_cert)
        SSL_CTX_set_custom_verify(ssl_ctx, SSL_VERIFY_PEER,
            verify_server_cert_callback);
    SSL_CTX_set_early_data_enabled(ssl_ctx, 1);

    transpa_len = gen_trans_params(enc_sess, trans_params,
                                                    sizeof(trans_params));
    if (transpa_len < 0)
    {
        SSL_CTX_free(ssl_ctx);
        goto err;
    }

    enc_sess->esi_ssl = SSL_new(ssl_ctx);
    if (!enc_sess->esi_ssl)
    {
        SSL_CTX_free(ssl_ctx);
        LSQ_ERROR("cannot create SSL object: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    if (!(SSL_set_quic_method(enc_sess->esi_ssl, &cry_quic_method)))
    {
        LSQ_INFO("could not set stream method");
        goto err;
    }
    maybe_setup_key_logging(enc_sess);
    if (1 != SSL_set_quic_transport_params(enc_sess->esi_ssl, trans_params,
                                                            transpa_len))
    {
        LSQ_ERROR("cannot set QUIC transport params: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    if (0 != SSL_set_alpn_protos(enc_sess->esi_ssl, am->alpn, am->alpn[0] + 1))
    {
        LSQ_ERROR("cannot set ALPN: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    if (1 != SSL_set_tlsext_host_name(enc_sess->esi_ssl,
                                                    enc_sess->esi_hostname))
    {
        LSQ_ERROR("cannot set hostname: %s",
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    free(enc_sess->esi_hostname);
    enc_sess->esi_hostname = NULL;
    if (enc_sess->esi_zero_rtt_buf)
    {
        ssl_session = maybe_create_SSL_SESSION(enc_sess, ssl_ctx);
        if (ssl_session)
        {
            if (SSL_set_session(enc_sess->esi_ssl, ssl_session))
                enc_sess->esi_flags |= ESI_USE_SSL_TICKET;
            else
                LSQ_WARN("cannot set session");
        }
    }

    SSL_set_ex_data(enc_sess->esi_ssl, s_idx, enc_sess);
    SSL_set_connect_state(enc_sess->esi_ssl);

    LSQ_DEBUG("initialized client enc session");
    enc_sess->esi_flags |= ESI_INITIALIZED;
    return 0;

  err:
    return -1;
#undef hexbuf
}


struct crypto_params
{
    const EVP_AEAD      *aead;
    const EVP_MD        *md;
    const EVP_CIPHER    *hp;
    gen_hp_mask_f        gen_hp_mask;
};


static int
get_crypto_params (const struct enc_sess_iquic *enc_sess,
                                                struct crypto_params *params)
{
    const SSL_CIPHER *cipher;
    unsigned key_sz, iv_sz;
    uint32_t id;

    cipher = SSL_get_current_cipher(enc_sess->esi_ssl);
    id = SSL_CIPHER_get_id(cipher);

    LSQ_DEBUG("Negotiated cipher ID is 0x%"PRIX32, id);

    /* RFC 8446, Appendix B.4 */
    switch (id)
    {
    case 0x03000000 | 0x1301:       /* TLS_AES_128_GCM_SHA256 */
        params->md          = EVP_sha256();
        params->aead        = EVP_aead_aes_128_gcm();
        params->hp          = EVP_aes_128_ecb();
        params->gen_hp_mask = gen_hp_mask_aes;
        break;
    case 0x03000000 | 0x1302:       /* TLS_AES_256_GCM_SHA384 */
        params->md          = EVP_sha384();
        params->aead        = EVP_aead_aes_256_gcm();
        params->hp          = EVP_aes_256_ecb();
        params->gen_hp_mask = gen_hp_mask_aes;
        break;
    case 0x03000000 | 0x1303:       /* TLS_CHACHA20_POLY1305_SHA256 */
        params->md          = EVP_sha256();
        params->aead        = EVP_aead_chacha20_poly1305();
        params->hp          = NULL;
        params->gen_hp_mask = gen_hp_mask_chacha20;
        break;
    default:
        /* TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256 are not
         * supported by BoringSSL (grep for \b0x130[45]\b).
         */
        LSQ_DEBUG("unsupported cipher 0x%"PRIX32, id);
        return -1;
    }

    key_sz = EVP_AEAD_key_length(params->aead);
    if (key_sz > sizeof(enc_sess->esi_crypto_pair[0]->ykp_ctx[0].yk_key_buf))
    {
        LSQ_DEBUG("key size %u is too large", key_sz);
        return -1;
    }

    iv_sz = EVP_AEAD_nonce_length(params->aead);
    if (iv_sz < 8)
        iv_sz = 8;  /* [draft-ietf-quic-tls-11], Section 5.3 */
    if (iv_sz > sizeof(enc_sess->esi_crypto_pair[0]->ykp_ctx[0].yk_iv_buf))
    {
        LSQ_DEBUG("iv size %u is too large", iv_sz);
        return -1;
    }

    if (key_sz > sizeof(enc_sess->esi_crypto_pair[0]->ykp_ctx[0].yk_hp_buf))
    {
        LSQ_DEBUG("PN size %u is too large", key_sz);
        return -1;
    }

    return 0;
}


static struct ssl_st *
iquic_esfi_get_ssl (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    return enc_sess->esi_ssl;
}


static enum iquic_handshake_status
iquic_esfi_handshake (struct enc_sess_iquic *enc_sess)
{
    int s, err, have_alpn;
    const unsigned char *alpn;
    unsigned alpn_len;
    enum lsquic_hsk_status hsk_status;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    s = SSL_do_handshake(enc_sess->esi_ssl);
    if (s <= 0)
    {
        err = SSL_get_error(enc_sess->esi_ssl, s);
        switch (err)
        {
        case SSL_ERROR_WANT_READ:
            LSQ_DEBUG("retry read");
            return IHS_WANT_READ;
        case SSL_ERROR_WANT_WRITE:
            LSQ_DEBUG("retry write");
            return IHS_WANT_WRITE;
        case SSL_EARLY_DATA_REJECTED:   /* XXX should this be included here? */
        case SSL_ERROR_EARLY_DATA_REJECTED:
            LSQ_DEBUG("early data rejected");
            hsk_status = LSQ_HSK_0RTT_FAIL;
            goto err;
        default:
            LSQ_DEBUG("handshake: %s", ERR_error_string(err, errbuf));
            hsk_status = LSQ_HSK_FAIL;
            goto err;
        }
    }

    if (SSL_in_early_data(enc_sess->esi_ssl))
    {
        LSQ_DEBUG("in early data");
            return IHS_WANT_READ;
    }

    hsk_status = LSQ_HSK_OK;
    LSQ_DEBUG("handshake reported complete");
    EV_LOG_HSK_COMPLETED(LSQUIC_LOG_CONN_ID);
    /* The ESI_USE_SSL_TICKET flag indicates if the client attempted 0-RTT.
     * If the handshake is complete, and the client attempted 0-RTT, it
     * must have succeeded.
     */
    if (enc_sess->esi_flags & ESI_USE_SSL_TICKET)
    {
        hsk_status = LSQ_HSK_0RTT_OK;
        EV_LOG_ZERO_RTT(LSQUIC_LOG_CONN_ID);
    }
    SSL_get0_alpn_selected(enc_sess->esi_ssl, &alpn, &alpn_len);
    have_alpn = alpn && alpn_len == enc_sess->esi_alpn[0]
                        && 0 == memcmp(alpn, enc_sess->esi_alpn + 1, alpn_len);
    if (have_alpn)
        LSQ_DEBUG("Selected ALPN %.*s", (int) alpn_len, (char *) alpn);
    else
        LSQ_INFO("No ALPN is selected");

    enc_sess->esi_flags |= ESI_HANDSHAKE_OK;
    enc_sess->esi_conn->cn_if->ci_hsk_done(enc_sess->esi_conn, hsk_status);


    return IHS_STOP;    /* XXX: what else can come on the crypto stream? */

  err:
    LSQ_DEBUG("handshake failed");
    enc_sess->esi_conn->cn_if->ci_hsk_done(enc_sess->esi_conn, hsk_status);
    return IHS_STOP;
}


static enum iquic_handshake_status
iquic_esfi_post_handshake (struct enc_sess_iquic *enc_sess)
{
    int s;

    s = SSL_process_quic_post_handshake(enc_sess->esi_ssl);
    LSQ_DEBUG("SSL_process_quic_post_handshake() returned %d", s);
    if (s == 1)
        return IHS_WANT_READ;
    else
    {
        LSQ_DEBUG("TODO: abort connection?");
        return IHS_STOP;
    }
}


static int
iquic_esfi_get_peer_transport_params (enc_session_t *enc_session_p,
                                        struct transport_params *trans_params)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    const uint8_t *params_buf;
    size_t bufsz;
    char params_str[0x200];

    SSL_get_peer_quic_transport_params(enc_sess->esi_ssl, &params_buf, &bufsz);
    if (!params_buf)
    {
        LSQ_DEBUG("no peer transport parameters");
        return -1;
    }

    LSQ_DEBUG("have peer transport parameters (%zu bytes)", bufsz);
    if (0 > lsquic_tp_decode(params_buf, bufsz,
                                                trans_params))
    {
        lsquic_hexdump(params_buf, bufsz, params_str, sizeof(params_str));
        LSQ_DEBUG("could not parse peer transport parameters (%zd bytes):\n%s",
            bufsz, params_str);
        return -1;
    }

    if ((enc_sess->esi_flags & ESI_ODCID) )
    {
        if (!(trans_params->tp_flags & TRAPA_ORIGINAL_CID))
        {
            LSQ_DEBUG("server did not produce original DCID (ODCID)");
            return -1;
        }
        if (LSQUIC_CIDS_EQ(&enc_sess->esi_odcid,
                                        &trans_params->tp_original_cid))
            LSQ_DEBUG("ODCID values match");
        else
        {
            if (LSQ_LOG_ENABLED(LSQ_LOG_DEBUG))
            {
                char cidbuf[2][MAX_CID_LEN * 2 + 1];
                lsquic_cid2str(&enc_sess->esi_odcid, cidbuf[0]);
                lsquic_cid2str(&trans_params->tp_original_cid, cidbuf[1]);
                LSQ_DEBUG("server provided ODCID %s that does not match "
                    "our ODCID %s", cidbuf[1], cidbuf[0]);
            }
            return -1;
        }
    }

    return 0;
}


static void
iquic_esfi_destroy (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    struct frab_list *fral;
    LSQ_DEBUG("destroy");
    for (fral = enc_sess->esi_frals; fral < enc_sess->esi_frals
            + sizeof(enc_sess->esi_frals) / sizeof(enc_sess->esi_frals[0]);
                ++fral)
        lsquic_frab_list_cleanup(fral);
    if (enc_sess->esi_keylog_handle)
        enc_sess->esi_enpub->enp_kli->kli_close(enc_sess->esi_keylog_handle);
    if (enc_sess->esi_ssl)
        SSL_free(enc_sess->esi_ssl);
    free(enc_sess->esi_zero_rtt_buf);
    free(enc_sess->esi_hostname);
    free(enc_sess);
}


/* See [draft-ietf-quic-tls-14], Section 4 */
static const enum enc_level hety2el[] =
{
    [HETY_NOT_SET]   = ENC_LEV_FORW,
    [HETY_VERNEG]    = 0,
    [HETY_INITIAL]   = ENC_LEV_CLEAR,
    [HETY_RETRY]     = 0,
    [HETY_HANDSHAKE] = ENC_LEV_INIT,
    [HETY_0RTT]      = ENC_LEV_EARLY,
};


static const enum header_type pns2hety[] =
{
    [PNS_INIT]  = HETY_INITIAL,
    [PNS_HSK]   = HETY_HANDSHAKE,
    [PNS_APP]   = HETY_NOT_SET,
};


static const enum enc_level pns2enc_level[] =
{
    [PNS_INIT]  = ENC_LEV_CLEAR,
    [PNS_HSK]   = ENC_LEV_INIT,
    [PNS_APP]   = ENC_LEV_FORW,
};


static enum enc_packout
iquic_esf_encrypt_packet (enc_session_t *enc_session_p,
    const struct lsquic_engine_public *enpub, const struct lsquic_conn *lconn,
    struct lsquic_packet_out *packet_out)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    unsigned char *dst;
    const struct crypto_ctx_pair *pair;
    const struct crypto_ctx *crypto_ctx;
    enum enc_level enc_level;
    unsigned char nonce_buf[ sizeof(crypto_ctx->yk_iv_buf) + 8 ];
    unsigned char *nonce, *begin_xor;
    lsquic_packno_t packno;
    size_t out_sz, dst_sz;
    int header_sz;
    int ipv6;
    unsigned packno_off, packno_len, sample_off;
    enum packnum_space pns;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    assert(lconn == enc_sess->esi_conn);

    pns = lsquic_packet_out_pns(packet_out);
    /* TODO Obviously, will need more logic for 0-RTT */
    enc_level = pns2enc_level[ pns ];
    packet_out->po_header_type = pns2hety[ pns ];
    pair = enc_sess->esi_crypto_pair[ enc_level ];
    if (!pair)
    {
        LSQ_WARN("no crypto context to encrypt at level %s",
                                                lsquic_enclev2str[enc_level]);
        return -1;
    }

    dst_sz = lconn->cn_pf->pf_packout_size(lconn, packet_out);
    ipv6 = lsquic_conn_peer_ipv6(lconn);
    dst = enpub->enp_pmi->pmi_allocate(enpub->enp_pmi_ctx,
                                            lconn->cn_peer_ctx, dst_sz, ipv6);
    if (!dst)
    {
        LSQ_DEBUG("could not allocate memory for outgoing packet of size %zd",
                                                                        dst_sz);
        return ENCPA_NOMEM;
    }

    crypto_ctx = &pair->ykp_ctx[ 0 ];

    if (UNLIKELY(0 == (crypto_ctx->yk_flags & YK_INITED)))
    {
        LSQ_WARN("encrypt crypto context at level %s not initialized",
                                                lsquic_enclev2str[enc_level]);
        return -1;
    }

    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - crypto_ctx->yk_iv_sz + 8;
    memcpy(nonce, crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
    packno = packet_out->po_packno;
    if (s_log_seal_and_open)
        LSQ_DEBUG("seal: iv: %s; packno: 0x%"PRIX64,
            HEXSTR(crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz, s_str), packno);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    header_sz = lconn->cn_pf->pf_gen_reg_pkt_header(lconn, packet_out, dst,
                                                                        dst_sz);
    if (header_sz < 0)
        goto err;

    if (s_log_seal_and_open)
    {
        LSQ_DEBUG("seal: nonce (%u bytes): %s", crypto_ctx->yk_iv_sz,
            HEXSTR(nonce, crypto_ctx->yk_iv_sz, s_str));
        LSQ_DEBUG("seal: ad (%u bytes): %s", header_sz,
            HEXSTR(dst, header_sz, s_str));
        LSQ_DEBUG("seal: in (%u bytes): %s", packet_out->po_data_sz,
            HEXSTR(packet_out->po_data, packet_out->po_data_sz, s_str));
    }
    if (!EVP_AEAD_CTX_seal(&crypto_ctx->yk_aead_ctx, dst + header_sz, &out_sz,
                dst_sz - header_sz, nonce, crypto_ctx->yk_iv_sz, packet_out->po_data,
                packet_out->po_data_sz, dst, header_sz))
    {
        LSQ_WARN("cannot seal packet #%"PRIu64": %s", packet_out->po_packno,
            ERR_error_string(ERR_get_error(), errbuf));
        goto err;
    }
    assert(out_sz == dst_sz - header_sz);

    lconn->cn_pf->pf_packno_info(lconn, packet_out, &packno_off, &packno_len);
    sample_off = packno_off + 4;
    if (sample_off + IQUIC_TAG_LEN > dst_sz)
        sample_off = dst_sz - IQUIC_TAG_LEN;
    apply_hp(enc_sess, crypto_ctx, pair, dst, packno_off, packno_len);

    packet_out->po_enc_data    = dst;
    packet_out->po_enc_data_sz = dst_sz;
    packet_out->po_sent_sz     = dst_sz;
    packet_out->po_flags &= ~PO_IPv6;
    packet_out->po_flags |= PO_ENCRYPTED|PO_SENT_SZ|(enc_level << POLEV_SHIFT)
                         |(ipv6 << POIPv6_SHIFT);
    return ENCPA_OK;

  err:
    enpub->enp_pmi->pmi_return(enpub->enp_pmi_ctx, lconn->cn_peer_ctx, dst,
                                                                        ipv6);
    return ENCPA_BADCRYPT;
}


static enum dec_packin
iquic_esf_decrypt_packet (enc_session_t *enc_session_p,
        struct lsquic_engine_public *enpub, const struct lsquic_conn *lconn,
        struct lsquic_packet_in *packet_in)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    unsigned char *dst;
    const struct crypto_ctx_pair *pair;
    const struct crypto_ctx *crypto_ctx;
    unsigned char nonce_buf[ sizeof(crypto_ctx->yk_iv_buf) + 8 ];
    unsigned char *nonce, *begin_xor;
    unsigned sample_off, packno_len;
    enum enc_level enc_level;
    enum packnum_space pns;
    lsquic_packno_t packno;
    size_t out_sz;
    enum dec_packin dec_packin;
    const size_t dst_sz = 1370;
    char errbuf[ERR_ERROR_STRING_BUF_LEN];

    dst = lsquic_mm_get_1370(&enpub->enp_mm);
    if (!dst)
    {
        LSQ_WARN("cannot allocate memory to copy incoming packet data");
        dec_packin = DECPI_NOMEM;
        goto err;
    }

    enc_level = hety2el[packet_in->pi_header_type];
    pair = enc_sess->esi_crypto_pair[ enc_level ];
    if (!pair)
    {
        LSQ_DEBUG("cannot decrypt packet type %s at level %s yet",
            lsquic_hety2str[packet_in->pi_header_type],
            lsquic_enclev2str[enc_level]);
        dec_packin = DECPI_NOT_YET;
        goto err;
    }

    crypto_ctx = &pair->ykp_ctx[ 1 ];

    if (UNLIKELY(0 == (crypto_ctx->yk_flags & YK_INITED)))
    {
        LSQ_WARN("decrypt crypto context at level %s not initialized",
                                                lsquic_enclev2str[enc_level]);
        return -1;
    }

    /* Decrypt packet number.  After this operation, packet_in is adjusted:
     * the packet number becomes part of the header.
     */
    sample_off = packet_in->pi_header_sz + 4;
    if (sample_off + IQUIC_TAG_LEN > packet_in->pi_data_sz)
    {
        LSQ_INFO("packet data is too short: %hu bytes",
                                                packet_in->pi_data_sz);
        dec_packin = DECPI_TOO_SHORT;
        goto err;
    }
    memcpy(dst, packet_in->pi_data, sample_off);
    packet_in->pi_packno =
    packno = strip_hp(enc_sess, crypto_ctx, pair,
        packet_in->pi_data + sample_off,
        dst, packet_in->pi_header_sz, &packno_len);

    if (s_log_seal_and_open)
        LSQ_DEBUG("open: iv: %s; packno: 0x%"PRIX64,
            HEXSTR(crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz, s_str), packno);
    /* Align nonce so we can perform XOR safely in one shot: */
    begin_xor = nonce_buf + sizeof(nonce_buf) - 8;
    begin_xor = (unsigned char *) ((uintptr_t) begin_xor & ~0x7);
    nonce = begin_xor - crypto_ctx->yk_iv_sz + 8;
    memcpy(nonce, crypto_ctx->yk_iv_buf, crypto_ctx->yk_iv_sz);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    packno = bswap_64(packno);
#endif
    *((uint64_t *) begin_xor) ^= packno;

    packet_in->pi_header_sz += packno_len;

    if (s_log_seal_and_open)
    {
        LSQ_DEBUG("open: nonce (%u bytes): %s", crypto_ctx->yk_iv_sz,
            HEXSTR(nonce, crypto_ctx->yk_iv_sz, s_str));
        LSQ_DEBUG("open: ad (%u bytes): %s", packet_in->pi_header_sz,
            HEXSTR(dst, packet_in->pi_header_sz, s_str));
        LSQ_DEBUG("open: in (%u bytes): %s", packet_in->pi_data_sz
            - packet_in->pi_header_sz, HEXSTR(packet_in->pi_data
            + packet_in->pi_header_sz, packet_in->pi_data_sz
            - packet_in->pi_header_sz, s_str));
    }
    if (!EVP_AEAD_CTX_open(&crypto_ctx->yk_aead_ctx,
                dst + packet_in->pi_header_sz, &out_sz,
                dst_sz - packet_in->pi_header_sz, nonce, crypto_ctx->yk_iv_sz,
                packet_in->pi_data + packet_in->pi_header_sz,
                packet_in->pi_data_sz - packet_in->pi_header_sz,
                dst, packet_in->pi_header_sz))
    {
        LSQ_INFO("cannot open packet #%"PRIu64": %s", packet_in->pi_packno,
            ERR_error_string(ERR_get_error(), errbuf));
        dec_packin = DECPI_BADCRYPT;
        goto err;
    }

    if (dst[0] & (0x0C << (packet_in->pi_header_type == HETY_NOT_SET)))
    {
        LSQ_DEBUG("reserved bits are not set to zero");
        dec_packin = DECPI_VIOLATION;
        goto err;
    }

    packet_in->pi_data_sz = packet_in->pi_header_sz + out_sz;
    if (packet_in->pi_flags & PI_OWN_DATA)
        lsquic_mm_put_1370(&enpub->enp_mm, packet_in->pi_data);
    packet_in->pi_data = dst;
    packet_in->pi_flags |= PI_OWN_DATA | PI_DECRYPTED
                        | (pair->ykp_enc_level << PIBIT_ENC_LEV_SHIFT);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "decrypted packet %"PRIu64,
                                                    packet_in->pi_packno);
    pns = lsquic_enclev2pns[enc_level];
    if (packet_in->pi_packno > enc_sess->esi_max_packno[pns])
        enc_sess->esi_max_packno[pns] = packet_in->pi_packno;
    return DECPI_OK;

  err:
    if (dst)
        lsquic_mm_put_1370(&enpub->enp_mm, dst);
    EV_LOG_CONN_EVENT(LSQUIC_LOG_CONN_ID, "could not decrypt packet (type %s, "
        "number %"PRIu64")", lsquic_hety2str[packet_in->pi_header_type],
                                                    packet_in->pi_packno);
    return dec_packin;
}


static int
iquic_esf_global_init (int flags)
{
    s_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (s_idx >= 0)
    {
        LSQ_LOG1(LSQ_LOG_DEBUG, "SSL extra data index: %d", s_idx);
        return 0;
    }
    else
    {
        LSQ_LOG1(LSQ_LOG_ERROR, "%s: could not select index", __func__);
        return -1;
    }
}


static void
iquic_esf_global_cleanup (void)
{
}


static void *
copy_X509 (void *cert)
{
    X509_up_ref(cert);
    return cert;
}


static struct stack_st_X509 *
iquic_esf_get_server_cert_chain (enc_session_t *enc_session_p)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;
    STACK_OF(X509) *chain;

    if (enc_sess->esi_ssl)
    {
        chain = SSL_get_peer_cert_chain(enc_sess->esi_ssl);
        return (struct stack_st_X509 *)
            sk_deep_copy((const _STACK *) chain, sk_X509_call_copy_func,
                copy_X509, sk_X509_call_free_func, (void(*)(void*))X509_free);
    }
    else
        return NULL;
}


static struct conn_cid_elem *
iquic_esfi_add_scid (const struct lsquic_engine_public *enpub,
                                                    struct lsquic_conn *lconn)
{
    struct conn_cid_elem *cce;

    if (enpub->enp_settings.es_scid_len)
    {
        for (cce = lconn->cn_cces; cce < END_OF_CCES(lconn); ++cce)
            if (!(lconn->cn_cces_mask & (1 << (cce - lconn->cn_cces))))
                break;
    }
    else if (0 == lconn->cn_cces_mask)
        cce = lconn->cn_cces;
    else
        cce = END_OF_CCES(lconn);

    if (cce >= END_OF_CCES(lconn))
    {
        LSQ_LOG1(LSQ_LOG_DEBUG, "cannot find slot for new SCID");
        return NULL;
    }

    if (enpub->enp_settings.es_scid_len)
        generate_cid(&cce->cce_cid, enpub->enp_settings.es_scid_len);
    lconn->cn_cces_mask |= 1 << (cce - lconn->cn_cces);
    LSQ_LOG1C(LSQ_LOG_DEBUG, "generated and assigned SCID %"CID_FMT,
                                                    CID_BITS(&cce->cce_cid));
    return cce;
}


int
iquic_esfi_reset_dcid (enc_session_t *enc_session_p, const lsquic_cid_t *dcid)
{
    struct enc_sess_iquic *const enc_sess = enc_session_p;

    enc_sess->esi_odcid = enc_sess->esi_conn->cn_dcid;
    enc_sess->esi_flags |= ESI_ODCID;
    enc_sess->esi_conn->cn_dcid = *dcid;
    /* TODO: free previous handshake keys */
    if (0 == setup_handshake_keys(enc_sess, dcid))
    {
        LSQ_INFOC("reset DCID to %"CID_FMT, CID_BITS(dcid));
        return 0;
    }
    else
        return -1;
}


const struct enc_session_funcs_iquic lsquic_enc_session_iquic_id20 =
{
    .esfi_add_scid       = iquic_esfi_add_scid,
    .esfi_create_client  = iquic_esfi_create_client,
    .esfi_destroy        = iquic_esfi_destroy,
    .esfi_get_ssl        = iquic_esfi_get_ssl,
    .esfi_get_peer_transport_params
                         = iquic_esfi_get_peer_transport_params,
    .esfi_reset_dcid     = iquic_esfi_reset_dcid,
};


const struct enc_session_funcs_common lsquic_enc_session_common_id20 =
{
    .esf_encrypt_packet  = iquic_esf_encrypt_packet,
    .esf_decrypt_packet  = iquic_esf_decrypt_packet,
    .esf_global_cleanup  = iquic_esf_global_cleanup,
    .esf_global_init     = iquic_esf_global_init,
    .esf_tag_len         = IQUIC_TAG_LEN,
    .esf_get_server_cert_chain
                         = iquic_esf_get_server_cert_chain,
};


typedef char enums_have_the_same_value[
    (int) ssl_encryption_initial     == (int) ENC_LEV_CLEAR &&
    (int) ssl_encryption_early_data  == (int) ENC_LEV_EARLY &&
    (int) ssl_encryption_handshake   == (int) ENC_LEV_INIT  &&
    (int) ssl_encryption_application == (int) ENC_LEV_FORW      ? 1 : -1];

static int
cry_sm_set_encryption_secret (SSL *ssl, enum ssl_encryption_level_t level,
                    const uint8_t *read_secret, const uint8_t *write_secret,
                    size_t secret_len)
{
    struct enc_sess_iquic *enc_sess;
    struct crypto_ctx_pair *pair;
    struct crypto_params crypa;
    int i;
    const enum enc_level enc_level = (enum enc_level) level;
    const uint8_t *secrets[2];
    char errbuf[ERR_ERROR_STRING_BUF_LEN];
#define hexbuf errbuf

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (!enc_sess)
        return 0;

    if (enc_sess->esi_crypto_pair[enc_level])
    {   /* TODO: handle key phase */
        LSQ_ERROR("secret on level %u already exists", enc_level);
        return 0;
    }

    if (0 != get_crypto_params(enc_sess, &crypa))
        return 0;

    if (enc_level != ENC_LEV_EARLY)
        secrets[0] = write_secret, secrets[1] = read_secret;
    else
        secrets[1] = write_secret, secrets[0] = read_secret;

    pair = calloc(1, sizeof(*pair));
    if (!pair)
        return 0;

    LSQ_DEBUG("set encryption for level %u", enc_level);
    for (i = 1; i >= 0; --i)
    {
        if (secrets[i])
        {
            if (enc_sess->esi_flags & ESI_LOG_SECRETS)
                LSQ_DEBUG("new %s secret: %s", i ? "server" : "client",
                                    HEXSTR(secrets[i], secret_len, hexbuf));
            if (0 != init_crypto_ctx(&pair->ykp_ctx[i], crypa.md,
                        crypa.aead, secrets[i], secret_len, enc_sess->esi_dir[i]))
                goto err;
        }
        else
            assert(level == ssl_encryption_early_data);
    }

    if (enc_sess->esi_flags & ESI_LOG_SECRETS)
        log_crypto_pair(enc_sess, pair, "new");

    pair->ykp_enc_level  = enc_level;
    pair->ykp_hp         = crypa.hp;
    pair->ykp_gen_hp_mask= crypa.gen_hp_mask;
    enc_sess->esi_crypto_pair[enc_level] = pair;
    return 1;

  err:
    cleanup_crypto_ctx(&pair->ykp_ctx[0]);
    cleanup_crypto_ctx(&pair->ykp_ctx[1]);
    free(pair);
    return 0;
#undef hexbuf
}


static int
cry_sm_write_message (SSL *ssl, enum ssl_encryption_level_t level,
                                            const uint8_t *data, size_t len)
{
    struct enc_sess_iquic *enc_sess;
    void *stream;
    ssize_t nw;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (!enc_sess)
        return 0;

    stream = enc_sess->esi_streams[level];
    if (!stream)
        return 0;

    if (enc_sess->esi_flags & ESI_ON_WRITE)
        nw = enc_sess->esi_cryst_if->csi_write(stream, data, len);
    else
    {
        LSQ_DEBUG("not in on_write event: buffer in a frab list");
        if (0 == lsquic_frab_list_write(&enc_sess->esi_frals[level], data, len))
        {
            if (!lsquic_frab_list_empty(&enc_sess->esi_frals[level]))
                enc_sess->esi_cryst_if->csi_wantwrite(stream, 1);
            nw = len;
        }
        else
            nw = -1;
    }

    if (nw >= 0 && (size_t) nw == len)
    {
        enc_sess->esi_last_w = (enum enc_level) level;
        LSQ_DEBUG("wrote %zu bytes to stream at encryption level %u",
            len, level);
        return 1;
    }
    else
    {
        LSQ_INFO("could not write %zu bytes: returned %zd", len, nw);
        return 0;
    }
}


static int
cry_sm_flush_flight (SSL *ssl)
{
    struct enc_sess_iquic *enc_sess;
    void *stream;
    unsigned level;
    int s;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (!enc_sess)
        return 0;

    level = enc_sess->esi_last_w;
    stream = enc_sess->esi_streams[level];
    if (!stream)
        return 0;

    if (lsquic_frab_list_empty(&enc_sess->esi_frals[level]))
    {
        s = enc_sess->esi_cryst_if->csi_flush(stream);
        return s == 0;
    }
    else
        /* Frab list will get flushed */    /* TODO: add support for
        recording flush points in frab list. */
        return 1;
}


static int
cry_sm_send_alert (SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
    struct enc_sess_iquic *enc_sess;

    enc_sess = SSL_get_ex_data(ssl, s_idx);
    if (!enc_sess)
        return 0;

    LSQ_INFO("got alert %"PRIu8, alert);
    enc_sess->esi_conn->cn_if->ci_tls_alert(enc_sess->esi_conn, alert);

    return 1;
}


static const SSL_QUIC_METHOD cry_quic_method =
{
    .set_encryption_secrets = cry_sm_set_encryption_secret,
    .add_handshake_data     = cry_sm_write_message,
    .flush_flight           = cry_sm_flush_flight,
    .send_alert             = cry_sm_send_alert,
};


static lsquic_stream_ctx_t *
chsk_ietf_on_new_stream (void *stream_if_ctx, struct lsquic_stream *stream)
{
    struct enc_sess_iquic *const enc_sess = stream_if_ctx;
    enum enc_level enc_level;

    enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    if (enc_level != ENC_LEV_CLEAR)
    {
        LSQ_DEBUG("skip initialization of stream at level %u", enc_level);
        goto end;
    }

    if (
        0 != init_client(enc_sess))
    {
        LSQ_WARN("enc session could not be initialized");
        return NULL;
    }

    enc_sess->esi_cryst_if->csi_wantwrite(stream, 1);

    LSQ_DEBUG("handshake stream created successfully");

  end:
    return stream_if_ctx;
}


static void
chsk_ietf_on_close (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct enc_sess_iquic *const enc_sess = (struct enc_sess_iquic *) ctx;
    LSQ_DEBUG("crypto stream level %u is closed",
                (unsigned) enc_sess->esi_cryst_if->csi_enc_level(stream));
}


static const char *const ihs2str[] = {
    [IHS_WANT_READ]  = "want read",
    [IHS_WANT_WRITE] = "want write",
    [IHS_STOP]       = "stop",
};


static void
shake_stream (struct enc_sess_iquic *enc_sess,
                            struct lsquic_stream *stream, const char *what)
{
    enum iquic_handshake_status st;
    enum enc_level enc_level;
    int write;

    if (0 == (enc_sess->esi_flags & ESI_HANDSHAKE_OK))
        st = iquic_esfi_handshake(enc_sess);
    else
        st = iquic_esfi_post_handshake(enc_sess);
    enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    LSQ_DEBUG("enc level %s after %s: %s", lsquic_enclev2str[enc_level], what,
                                                                ihs2str[st]);
    switch (st)
    {
    case IHS_WANT_READ:
        write = !lsquic_frab_list_empty(&enc_sess->esi_frals[enc_level]);
        enc_sess->esi_cryst_if->csi_wantwrite(stream, write);
        enc_sess->esi_cryst_if->csi_wantread(stream, 1);
        break;
    case IHS_WANT_WRITE:
        enc_sess->esi_cryst_if->csi_wantwrite(stream, 1);
        enc_sess->esi_cryst_if->csi_wantread(stream, 0);
        break;
    default:
        assert(st == IHS_STOP);
        write = !lsquic_frab_list_empty(&enc_sess->esi_frals[enc_level]);
        enc_sess->esi_cryst_if->csi_wantwrite(stream, write);
        enc_sess->esi_cryst_if->csi_wantread(stream, 0);
        break;
    }
}


struct readf_ctx
{
    struct enc_sess_iquic  *enc_sess;
    enum enc_level          enc_level;
    int                     err;
};


static size_t
readf_cb (void *ctx, const unsigned char *buf, size_t len, int fin)
{
    struct readf_ctx *const readf_ctx = (void *) ctx;
    struct enc_sess_iquic *const enc_sess = readf_ctx->enc_sess;
    int s;
    size_t str_sz;
    char str[1500 * 5];

    s = SSL_provide_quic_data(enc_sess->esi_ssl,
                (enum ssl_encryption_level_t) readf_ctx->enc_level, buf, len);
    if (s)
    {
        LSQ_DEBUG("provided %zu bytes of %u-level data to SSL", len,
                                                        readf_ctx->enc_level);
        str_sz = lsquic_hexdump(buf, len, str, sizeof(str));
        LSQ_DEBUG("\n%.*s", (int) str_sz, str);
        return len;
    }
    else
    {
        LSQ_INFO("SSL_provide_quic_data returned false");
        readf_ctx->err++;
        return 0;
    }
}


static void
chsk_ietf_on_read (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct enc_sess_iquic *const enc_sess = (void *) ctx;
    enum enc_level enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    struct readf_ctx readf_ctx = { enc_sess, enc_level, 0, };
    ssize_t nread = enc_sess->esi_cryst_if->csi_readf(stream,
                                                    readf_cb, &readf_ctx);
    if (!(nread < 0 || readf_ctx.err))
        shake_stream(enc_sess, stream, "on_read");
    else
    {
        LSQ_WARN("TODO: abort connection");
    }
}


static void
maybe_write_from_fral (struct enc_sess_iquic *enc_sess,
                                                struct lsquic_stream *stream)
{
    enum enc_level enc_level = enc_sess->esi_cryst_if->csi_enc_level(stream);
    struct frab_list *const fral = &enc_sess->esi_frals[enc_level];
    struct lsquic_reader reader = {
        .lsqr_read  = lsquic_frab_list_read,
        .lsqr_size  = lsquic_frab_list_size,
        .lsqr_ctx   = fral,
    };
    ssize_t nw;

    if (lsquic_frab_list_empty(fral))
        return;

    nw = lsquic_stream_writef(stream, &reader);
    if (nw >= 0)
    {
        LSQ_DEBUG("wrote %zd bytes to stream from frab list", nw);
        (void) lsquic_stream_flush(stream);
        if (lsquic_frab_list_empty(fral))
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
chsk_ietf_on_write (struct lsquic_stream *stream, lsquic_stream_ctx_t *ctx)
{
    struct enc_sess_iquic *const enc_sess = (void *) ctx;

    maybe_write_from_fral(enc_sess, stream);

    enc_sess->esi_flags |= ESI_ON_WRITE;
    shake_stream(enc_sess, stream, "on_write");
    enc_sess->esi_flags &= ~ESI_ON_WRITE;
}


const struct lsquic_stream_if lsquic_cry_sm_if =
{
    .on_new_stream = chsk_ietf_on_new_stream,
    .on_read       = chsk_ietf_on_read,
    .on_write      = chsk_ietf_on_write,
    .on_close      = chsk_ietf_on_close,
};


