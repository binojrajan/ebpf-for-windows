// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    int
    bpf_map_get_fd_by_id_go(unsigned int map_id);
    unsigned int
    bpf_map_get_next_id_go(unsigned int map_id);
    int
    bpf_map_get_type_by_fd_go(int map_fd, char* mapname);
    uint64_t
    bpf_map_lookup_elem_go(int map_fd, uint64_t index, uint64_t value);

#ifdef __cplusplus
}
#endif