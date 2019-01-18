/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_purga.h -- Purgatory for CIDs
 *
 * This module keeps a set of CIDs that should be ignored for a period
 * of time.  It is used when a connection is closed: this way, late
 * packets will not create a new connection.
 */

#ifndef LSQUIC_PURGA_H
#define LSQUIC_PURGA_H 1

struct lsquic_purga;

/* Purgatory type is used to tell what action to take when a packet whose
 * CID is in the purgatory is received.
 */
enum purga_type
{
    PUTY_NOT_FOUND,     /* Return value only */
    PUTY_CONN_DELETED,  /* Connection was deleted */
    PUTY_CID_RETIRED,   /* CID was retired */
    PUTY_CID_RETRY,     /* Connection was told to retry */
};

struct lsquic_purga *
lsquic_purga_new (lsquic_time_t min_life);

void
lsquic_purga_add (struct lsquic_purga *, const lsquic_cid_t *, enum purga_type,
                                                                lsquic_time_t);

enum purga_type
lsquic_purga_contains (struct lsquic_purga *, const lsquic_cid_t *);

void
lsquic_purga_destroy (struct lsquic_purga *);

unsigned
lsquic_purga_cids_per_page (void);

#endif
