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

type Key struct {
	key C.ssh_key
}

func (k *Key) Free() {
	C.ssh_key_free(k.key)
}

func (k *Key) Hash(typ int) ([]byte, error) {
	var hash **C.uchar
	var size *C.size_t
	err := commonError(C.ssh_get_publickey_hash(k.key, C.enum_ssh_publickey_hash_type(typ), hash, size))
	if err != nil {
		return nil, err
	}
	data := make([]byte, *size)
	var i C.int = 0
	for ; i < C.int(*size); i++ {
		data[i] = byte(C.get_buffer_by_index(*hash, i))
	}
	return data, nil
}
