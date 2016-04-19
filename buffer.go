package libssh

/*
#cgo pkg-config: libssh
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libssh/libssh.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

type Buffer struct {
	ptr *C.struct_ssh_buffer_struct
}

func NewBuffer() (Buffer, error) {
	buf := Buffer{}
	buf.ptr = C.ssh_buffer_new()
	if buf.ptr == nil {
		return buf, errors.New("ssh_buffer_new() == nil")
	}
	return buf, nil
}

func (b Buffer) Free() {
	C.ssh_buffer_free(b.ptr)
}

func (b Buffer) AddRawData(data_ptr unsafe.Pointer, length C.uint32_t) error {
	if C.ssh_buffer_add_data(b.ptr, data_ptr, length) < 0 {
		return errors.New("Unable to add data to buffer")
	}
	return nil
}

func (b Buffer) AddData(data []byte) error {
	len := len(data)
	data_ptr := unsafe.Pointer(&data[0])
	return b.AddRawData(data_ptr, C.uint32_t(len))
}

// Get the length of the buffer from the current position.
func (b Buffer) Len() int {
	return int(C.ssh_buffer_get_len(b.ptr))
}

// Get the remaining data out of the buffer and adjust the read pointer.
func (b Buffer) Read(length int) []byte {
	if length <= 0 {
		return nil
	}
	buf := make([]C.uchar, length)
	ret := int(C.ssh_buffer_get_data(b.ptr, unsafe.Pointer(&buf[0]), C.uint32_t(length)))
	if ret == 0 {
		return nil
	}
	result := make([]byte, ret)
	for i := 0; i < ret; i++ {
		result[i] = byte(buf[i])
	}
	return result
}

// read all unread data
func (b Buffer) ReadAll() []byte {
	return b.Read(b.Len())
}

// Reinitialize a SSH buffer.
func (b Buffer) Reset() error {
	if C.ssh_buffer_reinit(b.ptr) < 0 {
		return errors.New("Fails to reinitialize buffer")
	}
	return nil
}
