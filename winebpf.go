// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

package winebpf

/*
#cgo CFLAGS: -I ../include
#cgo LDFLAGS: -L. -lwinebpf -L ../x64/Debug
#include <winebpf.h>
#include <stdint.h>

int bpf_map_get_fd_by_id_go(unsigned int map_id);
unsigned int bpf_map_get_next_id_go(unsigned int map_id);
int bpf_map_get_type_by_fd_go(int map_fd, char* mapname);
uint64_t bpf_map_lookup_elem_go(int map_fd, uint64_t index, uint64_t value);
*/
import "C"

import (
	"fmt"

	"github.com/rs/zerolog/log"
)

func MapGetNextID(mapid uint) (uint, error) {
	mapid2 := C.uint(mapid)
	nextid := uint(C.bpf_map_get_next_id_go(mapid2))

	log.Info().Msgf("Next id is  %d\n", nextid)

	if nextid == 0 {
		return nextid, fmt.Errorf("Did not find any more maps\n")
	}

	return nextid, nil
}

func MapTypeFromFD(mapfd int, mapname string) (int, error) {
	mapfd2 := C.int(mapfd)
	mapname2 := C.CString(mapname)
	maptype := int(C.bpf_map_get_type_by_fd_go(mapfd2, mapname2))

	log.Info().Msgf("Map name is  %s\n", mapname)
	log.Info().Msgf("Map type is  %d\n", maptype)

	if maptype < 0 {
		return maptype, fmt.Errorf("Did not find any more maps\n")
	}

	return maptype, nil
}

func MapFDFromID(mapid uint) int {
	mapid2 := C.uint(mapid)
	return int(C.bpf_map_get_fd_by_id_go(mapid2))
}

func Lookup(mapfd int, index uint64, value uint64) (uint64, uint64) {
	mapfd2 := C.int(mapfd)
	index2 := C.uint64_t(index)
	value2 := C.uint64_t(value)
	//var value uint64 = 0
	//var index uint64 = 0
	//ret := int(C.bpf_map_lookup_elem_go(mapfd2, unsafe.Pointer(&index), unsafe.Pointer(&value)))
	ret := uint64(C.bpf_map_lookup_elem_go(mapfd2, index2, value2))

	fmt.Println("index: %d\n", index2)
	fmt.Println("value: %d\n", value2)
	fmt.Println("ret: %d\n", ret)

	return ret, uint64(value2)
}

/*func Lookup(mapid uint, index uint64, value uint64) (int, uint64) {
	mapid2 := C.uint(mapid)
	index2 := C.uint64_t(index)
	value2 := C.uint64_t(value)

	//mapfd2 := C.bpf_map_get_fd_by_id_go(mapid2)
	//var value uint64 = 0
	//var index uint64 = 0
	//ret := int(C.bpf_map_lookup_elem_go(mapfd2, unsafe.Pointer(&index), unsafe.Pointer(&value)))
	ret := int(C.bpf_map_lookup_elem_go(mapid2, index2, value2))

	fmt.Println("index: %d\n", index2)
	fmt.Println("value: %d\n", value2)
	fmt.Println("ret: %d\n", ret)

	return ret, uint64(value2)
}*/