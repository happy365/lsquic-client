/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_HKDF_H
#define LSQUIC_HKDF_H 1

/* [draft-ietf-quic-tls-17] Section 5.2 */
#define HSK_SALT_BUF "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef" \
                     "\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0"
#define HSK_SALT ((unsigned char *) HSK_SALT_BUF)
#define HSK_SALT_SZ (sizeof(HSK_SALT_BUF) - 1)

#define CLIENT_LABEL "client in"
#define CLIENT_LABEL_SZ (sizeof(CLIENT_LABEL) - 1)
#define SERVER_LABEL "server in"
#define SERVER_LABEL_SZ (sizeof(SERVER_LABEL) - 1)

void
lsquic_qhkdf_expand (const struct env_md_st *, const unsigned char *secret,
            unsigned secret_len, const char *label, uint8_t label_len,
            unsigned char *out, uint16_t out_len);

#endif
