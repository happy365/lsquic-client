/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_hcso_writer.h
 */

#ifndef LSQUIC_HCSO_WRITER_H
#define LSQUIC_HCSO_WRITER_H 1

struct lsquic_engine_settings;
struct lsquic_stream;

struct hcso_writer
{
    struct lsquic_stream    *how_stream;
    struct frab_list         how_fral;
};

int
lsquic_hcso_write_settings (struct hcso_writer *,
                        const struct lsquic_engine_settings *, int);

extern const struct lsquic_stream_if *const lsquic_hcso_writer_if;

#endif
