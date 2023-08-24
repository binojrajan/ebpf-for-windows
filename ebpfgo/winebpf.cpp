// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers_platform.h"
#include "ebpf_structs.h"
#include "winebpf.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstddef>
#include <cstdio>
#include <io.h>

#define close _close

typedef struct _process_entry
{
    uint32_t count;
    wchar_t name[32];
} process_entry_t;

typedef unsigned long long uint64_t;

/*int
bpf_map_get_type_by_id_go(unsigned int map_id, char* mapname){
    bpf_map_info info;
    uint32_t info_size = sizeof(info);
    int map_fd = bpf_map_get_fd_by_id_go(map_id);

    printf("bpf_map_get_type_by_id_go map_fd %d\n", map_fd);

    if(bpf_obj_get_info_by_fd(map_fd, &info, &info_size) == 0)
    {
        printf("inside bpf_map_get_type_by_id_go if : %s %d\n",info.name, info.type);

        if (strcmp(info.name, mapname) == 0)
        {
            return info.type;
        }
    }

    return -1;
}*/

int
bpf_map_get_type_by_fd_go(int map_fd, char* mapname)
{
    bpf_map_info info;
    uint32_t info_size = sizeof(info);

    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_size) == 0) {
        printf("inside bpf_map_get_type_by_id_go if : %s %d\n", info.name, info.type);

        if (strcmp(info.name, mapname) == 0) {
            return info.type;
        }
    }

    return -1;
}

int
bpf_map_get_fd_by_id_go(unsigned int map_id)
{
    return bpf_map_get_fd_by_id(map_id);
}

unsigned int
bpf_map_get_next_id_go(unsigned int map_id)
{
    int ret = bpf_map_get_next_id(map_id, &map_id);
    if (ret == 0) {
        return map_id;
    }

    return 0;
}

/*int
bpf_map_lookup_elem_go(unsigned int map_fd, uint64_t index, uint64_t value){
    //bpf_map_lookup_elem_go(unsigned int map_fd, const void* index, void* value){
    //uint64_t index2 = *index;
    //uint64_t value2 = value;
     int fdclose = _close(map_fd);
    printf("1: fdclose return value is %d\n",fdclose);

    int ret = bpf_map_lookup_elem(map_fd, &index, &value);

    if(ret == 0) {
        printf("Successfully retrieved the map value\n");
    }
    else {
        printf("return value is %d\n",ret);
        //printf("Failed to retrieve the map value %ld : %ld\n",*(unsigned long*)index, *(unsigned long*)value);
        printf("Failed to retrieve the map value %ld : %ld\n",index, value);
    }

    //fclose(map_fd);
    fdclose = _close(map_fd);
    printf("2: fdclose return value is %d\n",fdclose);

    return value;
}*/

uint64_t
bpf_map_lookup_elem_go(int map_fd, uint64_t index, uint64_t value)
{
    // bpf_map_lookup_elem_go(unsigned int map_fd, const void* index, void* value){
    // uint64_t index2 = *index;
    // uint64_t value2 = value;
    // int fdclose = _close(map_fd);
    // printf("1: fdclose return value is %d\n",fdclose);
    // int map_fd = bpf_map_get_fd_by_id(map_id);
    // int fdclose = close(map_fd);
    int ret = bpf_map_lookup_elem(map_fd, &index, &value);

    if (ret == 0) {
        printf("Successfully retrieved the map value\n");
    } else {
        printf("Failed to retrieve the map value for fd %d\n", map_fd);
        printf("return value is %d\n", ret);
        // printf("Failed to retrieve the map value %ld : %ld\n",*(unsigned long*)index, *(unsigned long*)value);
        // printf("Failed to retrieve the map value %ld : %ld\n", index, value);
        return 0;
    }

    // fclose(map_fd);
    // int fdclose = close(map_fd);
    // printf("map_fd : %d\n", map_fd);
    // printf("2: fdclose return value is %d errorno : %d\n", fdclose, errno);

    return value;
}
