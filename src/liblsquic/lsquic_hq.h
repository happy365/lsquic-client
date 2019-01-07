/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hq.h -- HTTP over QUIC (HQ) types
 */

#ifndef LSQUIC_HQ_H
#define LSQUIC_HQ_H 1

/* [draft-ietf-quic-http-15] Section 4 */
enum hq_frame_type
{
    HQFT_DATA           = 0,
    HQFT_HEADERS        = 1,
    HQFT_PRIORITY       = 2,
    HQFT_CANCEL_PUSH    = 3,
    HQFT_SETTINGS       = 4,
    HQFT_PUSH_PROMISE   = 5,
    HQFT_GOAWAY         = 7,
    HQFT_MAX_PUSH_ID    = 0xD,
};


enum hq_el_type
{
    HQET_REQ_STREAM     = 0,
    HQET_PUSH_STREAM    = 1,
    HQET_PLACEHOLDER    = 2,
    HQET_ROOT           = 3,
};

#define HQ_PT_SHIFT 6
#define HQ_DT_SHIFT 4


enum hq_setting_id
{
    HQSID_HEADER_TABLE_SIZE     = 1,
    HQSID_NUM_PLACEHOLDERS      = 3,
    HQSID_MAX_HEADER_LIST_SIZE  = 6,
    HQSID_QPACK_BLOCKED_STREAMS = 7,
};

/* As of 12/18/2018: */
#define HQ_DF_HEADER_TABLE_SIZE 0
#define HQ_DF_NUM_PLACEHOLDERS 0
#define HQ_DF_MAX_HEADER_LIST_SIZE 0
#define HQ_DF_QPACK_BLOCKED_STREAMS 0

struct hq_priority
{
    lsquic_stream_id_t  hqp_prio_id;
    lsquic_stream_id_t  hqp_dep_id;
    enum hq_el_type     hqp_prio_type:8;
    enum hq_el_type     hqp_dep_type:8;
    signed char         hqp_exclusive;
    uint8_t             hqp_weight;
};

#define HQP_WEIGHT(p) ((p)->hqp_weight + 1)

enum hq_uni_stream_type
{
    HQUST_CONTROL   = 'C',
    HQUST_PUSH      = 'P',
    HQUST_QPACK_ENC = 'H',
    HQUST_QPACK_DEC = 'h',
};

extern const char *const lsquic_hqelt2str[];

/* [draft-ietf-quic-http-17] Section 8.1 */
enum http_error_code
{
    HEC_NO_ERROR                 =  0x00,
    HEC_WRONG_SETTING_DIRECTION  =  0x01,
    HEC_PUSH_REFUSED             =  0x02,
    HEC_INTERNAL_ERROR           =  0x03,
    HEC_PUSH_ALREADY_IN_CACHE    =  0x04,
    HEC_REQUEST_CANCELLED        =  0x05,
    HEC_INCOMPLETE_REQUEST       =  0x06,
    HEC_CONNECT_ERROR            =  0x07,
    HEC_EXCESSIVE_LOAD           =  0x08,
    HEC_VERSION_FALLBACK         =  0x09,
    HEC_WRONG_STREAM             =  0x0A,
    HEC_PUSH_LIMIT_EXCEEDED      =  0x0B,
    HEC_DUPLICATE_PUSH           =  0x0C,
    HEC_UNKNOWN_STREAM_TYPE      =  0x0D,
    HEC_WRONG_STREAM_COUNT       =  0x0E,
    HEC_CLOSED_CRITICAL_STREAM   =  0x0F,
    HEC_WRONG_STREAM_DIRECTION   =  0x0010,
    HEC_EARLY_RESPONSE           =  0x0011,
    HEC_MISSING_SETTINGS         =  0x0012,
    HEC_UNEXPECTED_FRAME         =  0x0013,
    HEC_GENERAL_PROTOCOL_ERROR   =  0x00FF,
    HEC_MALFORMED_FRAME          =  0x0100,    /* add frame type */
};

#endif
