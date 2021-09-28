package MultiDaemon

import "github.com/gjlee0802/Golang-Study/ICS/Socket"

type MultiDaemon struct {
	_sockConn Socket.Socket
	_socks    []Socket.Socket
	_ports    []int
	_idxProc  int
}

func (d MultiDaemon) getSockConn() Socket.Socket {
	return d._sockConn
}


