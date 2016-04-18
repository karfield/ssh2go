package libssh

/*
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libssh/libssh.h>
*/
import "C"
import "unsafe"

type CStringWrapper struct {
	Ptr *C.char
}

func CString(str string) CStringWrapper {
	return CStringWrapper{C.CString(str)}
}

func (cstr CStringWrapper) Free() {
	C.free(unsafe.Pointer(cstr.Ptr))
}

func CBool(val bool) C.int {
	var ret C.int = 0
	if val {
		ret = 1
	}
	return ret
}

type Counter struct {
	InBytes    uint64
	OutBytes   uint64
	InPackets  uint64
	OutPackets uint64
}

func (c Counter) toCCounter() C.ssh_counter {
	return &C.struct_ssh_counter_struct{
		in_bytes:    C.uint64_t(c.InBytes),
		out_bytes:   C.uint64_t(c.OutBytes),
		in_packets:  C.uint64_t(c.InPackets),
		out_packets: C.uint64_t(c.OutPackets),
	}
}
