/* Copyright (c) 2017 - 2018 LiteSpeed Technologies Inc.  See LICENSE. */
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "lsquic.h"
#include "lsquic_types.h"
#include "lsquic_int_types.h"
#include "lsquic_purga.h"

#define LSQUIC_LOGGER_MODULE LSQLM_PURGA
#include "lsquic_logger.h"

struct purga_el
{
    lsquic_cid_t                puel_cid;
    enum purga_type             puel_type:8;
};

struct purga_page
{
    TAILQ_ENTRY(purga_page)     pupa_next;
    lsquic_time_t               pupa_last;
    unsigned                    pupa_count;
    struct purga_el             pupa_els[0];
};

#define PURGA_PAGE_SIZE 0x1000

#define CIDS_PER_PAGE ((PURGA_PAGE_SIZE - \
    offsetof(struct purga_page, pupa_els)) \
                            / sizeof(((struct purga_page *) 0)->pupa_els[0]))

#define PAGE_IS_FULL(page) ((page)->pupa_count >= CIDS_PER_PAGE)

TAILQ_HEAD(purga_pages, purga_page);

struct lsquic_purga
{
    lsquic_time_t              pur_min_life;
    struct purga_pages         pur_pages;
};


struct lsquic_purga *
lsquic_purga_new (lsquic_time_t min_life)
{
    struct lsquic_purga *purga;

    purga = calloc(1, sizeof(*purga));
    if (!purga)
    {
        LSQ_WARN("cannot create purgatory: malloc failed: %s", strerror(errno));
        return NULL;
    }

    purga->pur_min_life = min_life;
    TAILQ_INIT(&purga->pur_pages);
    LSQ_INFO("create purgatory, min life %"PRIu64" usec", min_life);

    return purga;
}


static struct purga_page *
purga_get_page (struct lsquic_purga *purga)
{
    struct purga_page *page;

    page = TAILQ_LAST(&purga->pur_pages, purga_pages);
    if (page && !PAGE_IS_FULL(page))
        return page;

    page = malloc(PURGA_PAGE_SIZE);
    if (!page)
    {
        LSQ_INFO("failed to allocate page: %s", strerror(errno));
        return NULL;
    }

    page->pupa_count = 0;
    page->pupa_last  = 0;
    TAILQ_INSERT_TAIL(&purga->pur_pages, page, pupa_next);
    LSQ_DEBUG("allocated new page");
    return page;
}


void
lsquic_purga_add (struct lsquic_purga *purga, const lsquic_cid_t *cid,
                                    enum purga_type putype, lsquic_time_t now)
{
    struct purga_page *page;

    page = purga_get_page(purga);
    if (!page)
        return;     /* We do best effort, nothing to do if malloc fails */

    page->pupa_els[ page->pupa_count++ ] = (struct purga_el) { *cid, putype, };
    LSQ_DEBUGC("added %"CID_FMT" to the set", CID_BITS(cid));
    if (PAGE_IS_FULL(page))
    {
        LSQ_DEBUG("last page is full, set timestamp to %"PRIu64, now);
        page->pupa_last = now;
    }

    while ((page = TAILQ_FIRST(&purga->pur_pages))
                && PAGE_IS_FULL(page)
                && page->pupa_last + purga->pur_min_life < now)
    {
        LSQ_DEBUG("page at timestamp %"PRIu64" expired; now is %"PRIu64,
            page->pupa_last, now);
        TAILQ_REMOVE(&purga->pur_pages, page, pupa_next);
        free(page);
    }
}


enum purga_type
lsquic_purga_contains (struct lsquic_purga *purga, const lsquic_cid_t *cid)
{
    struct purga_page *page;
    unsigned i;

    /* TODO Use a smarter mechanism, perhaps a Cookoo filter lookup before
     *      doing a scan?
     */
    TAILQ_FOREACH(page, &purga->pur_pages, pupa_next)
        for (i = 0; i < page->pupa_count; ++i)
            if (LSQUIC_CIDS_EQ(&page->pupa_els[i].puel_cid, cid))
            {
                LSQ_DEBUGC("found %"CID_FMT, CID_BITS(cid));
                return page->pupa_els[i].puel_type;
            }

    LSQ_DEBUGC("%"CID_FMT" not found", CID_BITS(cid));
    return PUTY_NOT_FOUND;
}


void
lsquic_purga_destroy (struct lsquic_purga *purga)
{
    struct purga_page *page;

    while ((page = TAILQ_FIRST(&purga->pur_pages)))
    {
        TAILQ_REMOVE(&purga->pur_pages, page, pupa_next);
        free(page);
    }
    free(purga);
    LSQ_INFO("destroyed");
}


unsigned
lsquic_purga_cids_per_page (void)
{
    LSQ_DEBUG("CIDs per page: %zu", CIDS_PER_PAGE);
    return CIDS_PER_PAGE;
}
