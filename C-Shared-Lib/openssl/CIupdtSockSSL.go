package main
/*
#cgo LDFLAGS: -lssl -lcrypto
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// go 코드에서 openssl 라이브러리의 함수를 찾지 못하여 *_Wrap 이름의 함수를 정의하여 이를 호출하도록 한다.
// TODO : 공유라이브러리를 링크하여 SSL 함수 호출이 가능한지 테스트
void _SSL_Init_Wrap() {
	SSL_library_init();
	SSL_load_error_strings();
	return;
}
*/
import "C"
import (
	"fmt"
	"log"
	"net"
	"strconv"
	"syscall"
	"errors"
	_"unsafe"
)

// CPP의 CIupdtSockSSL 클래스를 대체하는 struct
type CIupdtSockSSL struct{
	m_sock	int
	m_ctx	*C.struct_SSL_CTX
	m_ssl	*C.struct_SSL
	m_cert   string
	mPrivkey string
}

// 기능 : 소켓 연결을 담당하는 _Connect 함수를 호출한 다음, SSL 연결을 담당하는 _SSL_Connect 함수를 호출한다.
func (s CIupdtSockSSL) Connect(ip string, port int, timeoutSec int64) error {
	var err error

	err = s._Connect(ip, port, timeoutSec)
	if err != nil {
		return err
	}

	return s._SSL_Connect()
}

// 참고 자료 :
// https://stackoverflow.com/questions/7986156/how-do-i-fill-out-the-syscall-sockaddr-structure-so-that-i-can-later-use-it-with/14331094
// https://golang.hotexamples.com/examples/syscall/SockaddrInet4/-/golang-sockaddrinet4-class-examples.html
// 기능 : 구조체의 내용을 채워 Sockaddr를 얻고, 소켓을 생성하고, timeout을 설정하고, Connect를 시도한다.
func (s CIupdtSockSSL) _Connect(ip string, port int, timeoutSec int64) error {
	var err error
	var sa syscall.Sockaddr	// interface

	//s._MakeSockAddr(&sa, ip, port)
	sa, st, err := s.getSockaddr("tcp4", ip+":"+strconv.Itoa(port))

	s.m_sock, err = syscall.Socket(st, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Fatal("syscall error : Socket")
		return err
	}
	s.SetTimeout(timeoutSec)

	err = syscall.Connect(s.m_sock, sa)
	if err != nil {
		log.Fatal("syscall error : Connect")
		return err
	}

	fmt.Println("Successfully Connected!")
	return nil
}

// 기능 : 소켓의 타임아웃(Connect를 호출할 때 언제까지 기다릴 것인지)을 설정한다.
func (s CIupdtSockSSL) SetTimeout(sec int64) {
	tv := syscall.Timeval{sec, 0}

	syscall.SetsockoptTimeval(s.m_sock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	syscall.SetsockoptTimeval(s.m_sock, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &tv)

	return
}

// CPP에서의 함수 이름 : _MakeSockAddr
// 기능 : IP 주소 버전(tcp4 / tcp6)에 Sockaddr 구조체 내용을 채워주고 Sockaddr interface, 소켓 타입, 오류 여부를 반환한다.
func (s CIupdtSockSSL) getSockaddr(network, addr string) (sa syscall.Sockaddr, soType int, err error) {
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

func (s CIupdtSockSSL) _SSL_SetupCtxServer() *C.struct_SSL_CTX {
	return nil
}


func (s CIupdtSockSSL) _SSL_Connect() error {
	return nil
}

func main(){
	mysock := CIupdtSockSSL{0, nil, nil, "", ""}
	C._SSL_Init_Wrap()
	mysock.Connect("127.0.0.1", 80, 1.0)
}