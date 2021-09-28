package Socket

import (
	"errors"
	"log"
	"net"
	"strconv"
	"syscall"
)

func SOCKET_Connect(ip string, port int) (SOCKET, error) {
	var err error
	var sa syscall.Sockaddr // interface
	var sock int

	sa, st, err := getSockaddr("tcp4", ip+":"+strconv.Itoa(port))

	sock, err = syscall.Socket(st, syscall.SOCK_STREAM, syscall.IPPROTO_IP)
	if err != nil {
		log.Fatal("syscall error : Socket")
		return -1, err
	}

	err = syscall.Connect(sock, sa)
	if err != nil {
		log.Fatal("syscall error : Connect")
		return -1, err
	}
	return SOCKET(sock), nil
}

func SOCKET_BindAndListen(port int) {
	var err error
	var sa syscall.Sockaddr
	var sock int

	sa, st, err := getSockaddr("tcp4", ip+":"+strconv.Itoa(port))
}

// 기능 : IP 주소 버전(tcp4 / tcp6)에 Sockaddr 구조체 내용을 채워주고 Sockaddr interface, 소켓 타입, 오류 여부를 반환한다.
func getSockaddr(network, addr string) (sa syscall.Sockaddr, soType int, err error) {
	// TODO: add support for tcp networks.

	if network != "tcp4" && network != "tcp6" {
		return nil, -1, errors.New("only tcp4 and tcp6 network is supported")
	}

	tcpAddr, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return nil, -1, err
	}

	switch network {
	case "tcp4":
		var sa4 syscall.SockaddrInet4
		sa4.Port = tcpAddr.Port
		copy(sa4.Addr[:], tcpAddr.IP.To4())
		return &sa4, syscall.AF_INET, nil
	case "tcp6":
		var sa6 syscall.SockaddrInet6
		sa6.Port = tcpAddr.Port
		copy(sa6.Addr[:], tcpAddr.IP.To16())
		if tcpAddr.Zone != "" {
			ifi, err := net.InterfaceByName(tcpAddr.Zone)
			if err != nil {
				return nil, -1, err
			}
			sa6.ZoneId = uint32(ifi.Index)
		}
		return &sa6, syscall.AF_INET6, nil
	default:
		return nil, -1, errors.New("Unknown network type " + network)
	}
}