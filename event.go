package libssh

/*
#cgo pkg-config: libssh
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libssh/libssh.h>

extern int event_add_fd(ssh_event event, socket_t fd, short events, void *userdata);
*/
import "C"
import "unsafe"

type Event struct {
	event C.ssh_event
}

func NewEvent() Event {
	ev := C.ssh_event_new()
	if ev != nil {
		return Event{ev}
	}
	return Event{}
}

func (e Event) Free() {
	C.ssh_event_free(e.event)
}

type EventCallback struct {
	OnSshEvent func(socketFd int, revents int) int
}

// Add a fd to the event and assign it a callback, when used in blocking mode.
//
// socketFd:
//  Socket that will be polled.
// pollEvents:
//	Poll events that will be monitored for the socket. i.e. POLLIN, POLLPRI, POLLOUT
// callback:
func (e Event) AddFd(socketFd int, pollEvents int, callback *EventCallback) error {
	return apiError("ssh_event_add_fd", C.event_add_fd(e.event, C.socket_t(socketFd), C.short(pollEvents), unsafe.Pointer(callback)))
}

//export event_callback
func event_callback(fd C.socket_t, revents C.int, userdata unsafe.Pointer) C.int {
	callback := (*EventCallback)(userdata)
	return C.int(callback.OnSshEvent(int(fd), int(revents)))
}

// remove the poll handle from session and assign them to a event, when used in
// blocking mode.
func (e Event) AddSession(session Session) error {
	// FIXME: removeCallback here
	return apiError("ssh_event_add_session", C.ssh_event_add_session(e.event, session.ptr))
}

// Poll all the sockets and sessions associated through an event object.
//
// If any of the events are set after the poll, the call back functions of the
// sessions or sockets will be called. This function should be called once
// within the programs main loop
//
// timeout:
// An upper limit on the time for which the poll will block, in milliseconds.
// Specifying a negative value means an infinite timeout. This parameter is
// passed to the poll( function.)
/*func (e Event) Poll(timeout int) error {
	return e.eventError(C.sh_event_dopoll(e.event, C.int(timeout)))
}*/

// Remove a socket fd from an event context.
func (e Event) RemoveFd(fd int) error {
	return apiError("ssh_event_remove_fd", C.ssh_event_remove_fd(e.event, C.socket_t(fd)))
}

// Remove a session object from an event context.
func (e Event) RemoveSession(session Session) error {
	return apiError("ssh_event_remove_session", C.ssh_event_remove_session(e.event, session.ptr))
}

func (e Event) Poll(timeout int) error {
	return apiError("ssh_event_dopoll", C.ssh_event_dopoll(e.event, C.int(timeout)))
}
