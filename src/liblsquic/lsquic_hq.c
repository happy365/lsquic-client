/* Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE. */
#include "lsquic_types.h"
#include "lsquic_hq.h"

const char *const lsquic_hqelt2str[] =
{
    [HQET_REQ_STREAM]   = "request stream",
    [HQET_PUSH_STREAM]  = "push stream",
    [HQET_PLACEHOLDER]  = "placeholder",
    [HQET_ROOT]         = "root of the tree",
};
