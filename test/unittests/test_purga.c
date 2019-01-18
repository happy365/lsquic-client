/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_logger.h"
#include "lsquic_purga.h"

int
main (int argc, char **argv)
{
    int opt;
    unsigned i, per_page;
    lsquic_cid_t cid;
    struct lsquic_purga *purga;

    while (-1 != (opt = getopt(argc, argv, "v")))
    {
        switch (opt)
        {
        case 'v':
            lsquic_log_to_fstream(stderr, 0);
            lsquic_logger_lopt("purga=debug");
            break;
        default:
            exit(EXIT_FAILURE);
        }
    }

    per_page = lsquic_purga_cids_per_page();
    purga = lsquic_purga_new(10);
    assert(purga);

    cid.len = 2;
    for (i = 0; i < per_page; ++i)
    {
        cid.idbuf[0] = 0;
        cid.idbuf[1] = i;
        lsquic_purga_add(purga, &cid, PUTY_CONN_DELETED, 20);
    }

    for (i = 0; i < per_page; ++i)
    {
        cid.idbuf[0] = 0;
        cid.idbuf[1] = i;
        assert(PUTY_CONN_DELETED == lsquic_purga_contains(purga, &cid));
    }

    ++cid.idbuf[1];
    lsquic_purga_add(purga, &cid, PUTY_CONN_DELETED, 31);

    for (i = 0; i < per_page; ++i)
    {
        cid.idbuf[0] = 0;
        cid.idbuf[1] = i;
        assert(PUTY_NOT_FOUND == lsquic_purga_contains(purga, &cid));
    }

    ++cid.idbuf[1];
    assert(PUTY_CONN_DELETED == lsquic_purga_contains(purga, &cid));

    exit(EXIT_SUCCESS);
}
