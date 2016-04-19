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
import "errors"

type Message struct {
	msg C.ssh_message
}

func (s *Session) RetrieveMessage() (Message, error) {
	msg := C.ssh_message_get(s.ptr)
	if msg != nil {
		return Message{msg}, nil
	}
	return Message{}, errors.New("ssh_message_get() == nil")
}

func (m Message) Free() {
	C.ssh_message_free(m.msg)
}

func (m Message) Type() int {
	return int(C.ssh_message_type(m.msg))
}

func (m Message) SubType() int {
	return int(C.ssh_message_subtype(m.msg))
}
