package libssh

/*
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libssh/libssh.h>

unsigned char get_buffer_by_index(unsigned char *buf, int index) {
	return buf[index];
}
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

func copyData(data interface{}, len interface{}) []byte {
	var (
		ptr    *C.uchar
		length int = 0
	)
	if p, ok := data.(*C.uchar); ok {
		ptr = p
	} else if p2, ok := data.(*C.char); ok {
		ptr = (*C.uchar)(unsafe.Pointer(p2))
	} else if p3, ok := data.(unsafe.Pointer); ok {
		ptr = (*C.uchar)(p3)
	} else {
		return []byte{}
	}
	if l, ok := len.(C.uint32_t); ok {
		length = int(l)
	} else if l2, ok := len.(C.size_t); ok {
		length = int(l2)
	} else if l3, ok := len.(C.int); ok {
		length = int(l3)
	}
	if length == 0 {
		return []byte{}
	}
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = byte(C.get_buffer_by_index(ptr, C.int(i)))
	}
	return buf
}
