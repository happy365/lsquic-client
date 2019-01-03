/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hcsi_reader.h -- HTTP Control Stream Incoming (HCSI) reader
 */

#ifndef LSQUIC_HCSI_READER_H
#define LSQUIC_HCSI_READER_H 1

struct lsquic_conn;


struct hcsi_callbacks
{
    void    (*on_priority)(void *ctx, const struct hq_priority *);
    void    (*on_cancel_push)(void *ctx, uint64_t push_id);
    void    (*on_max_push_id)(void *ctx, uint64_t push_id);
    /* Gets called at the *end* of the SETTING frame */
    void    (*on_settings_frame)(void *ctx);
    void    (*on_setting)(void *ctx, uint16_t setting_id, uint64_t value);
    void    (*on_goaway)(void *ctx, uint64_t stream_id);
    void    (*on_unexpected_frame)(void *ctx, enum hq_frame_type);
};


struct hcsi_reader
{
    enum {
        HR_READ_FRAME_LENGTH,
        HR_READ_FRAME_LENGTH_CONTINUE,
        HR_READ_FRAME_TYPE,
        HR_SKIPPING,
        HR_READ_SETTING_ID,
        HR_READ_SETTING_ID_CONTINUE,
        HR_READ_SETTING_VALUE,
        HR_READ_SETTING_VALUE_CONTINUE,
        HR_READ_PRIORITY_BEGIN,
        HR_READ_PRIO_ID,
        HR_READ_PRIO_ID_CONTINUE,
        HR_READ_DEP_ID,
        HR_READ_DEP_ID_CONTINUE,
        HR_READ_WEIGHT,
        HR_READ_VARINT,
        HR_READ_VARINT_CONTINUE,
        HR_ERROR,
    }                               hr_state;
    enum hq_frame_type              hr_frame_type:8;
    const struct lsquic_conn       *hr_conn;
    uint64_t                        hr_frame_length;
    struct varint_read_state        hr_varint_state;
    union
    {
        struct hq_priority      priority;
        struct {
            uint16_t            id;
        }                       settings;
    }                               hr_u;
    unsigned                        hr_nread;  /* Used for PRIORITY and SETTINGS frames */
    const struct hcsi_callbacks    *hr_cb;
    void                           *hr_ctx;
};


void
lsquic_hcsi_reader_init (struct hcsi_reader *, const struct lsquic_conn *,
                                const struct hcsi_callbacks *, void *cb_ctx);

int
lsquic_hcsi_reader_feed (struct hcsi_reader *, const void *buf, size_t bufsz);

#endif
