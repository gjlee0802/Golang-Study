package Socket

import (
	"syscall"
)

type SOCKET int

type Socket struct {
	_sock SOCKET
}

// TODO : Is this Correct????????????!!!
// This func keep call syscall.Close function until it successfully close the fd
func (s Socket) close() {
	// if s._sock is unique
	if s._sock >= 0 {
		for true {
			err := syscall.Close(int(s._sock))
			if err == nil || err == syscall.EINTR {
				break
			}
		}
	}
}

func (s Socket) _SetNew(sock SOCKET) {
	return
}

func (s Socket) attach(sock SOCKET) {
	return
}
