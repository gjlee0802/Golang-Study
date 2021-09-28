package Socket

import (
	"syscall"
)

type SOCKET int

type Socket struct {
	_sock *SOCKET
}

// TODO : shared_ptr?
func (s Socket) _SetNew(sock SOCKET) {
	s.close()
	if sock != -1 {
		*s._sock = sock
	}

	return
}

func (s Socket) connect(ip string, port int) {
	var err error
	var sock SOCKET
	sock, err = SOCKET_Connect(ip, port)
	if err != nil{
		// TODO : handle ERROR
	}
	s._SetNew(sock)
}

// TODO : Is this Correct????????????!!!
// This func keep call syscall.Close function until it successfully close the fd
func (s Socket) close() {
	// if s._sock is unique
	if *s._sock >= 0 {
		for true {
			err := syscall.Close(int(*s._sock))
			if err == nil || err == syscall.EINTR {
				break
			}
		}
	}
}



func (s Socket) attach(sock SOCKET) {
	s._SetNew(sock)
}

func (s Socket) detach() {
	return
}

func (s Socket) listen(port int) {
	//var sock SOCKET
	return
}