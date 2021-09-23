package main
/*
#cgo LDFLAGS:-lssl -lcrypto
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

// go 코드에서 define를 찾지 못하여 *_Wrap 이름의 함수를 정의하여 이를 호출하도록 한다.
void _SSL_Init_Wrap() {
	SSL_library_init();
	SSL_load_error_strings();
	return;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"syscall"
	"unsafe"
	_ "unsafe"
	"github.com/gjlee0802/Golang-Study/C-Shared-Lib/CIupdtSockSSL/SSL"
)

//#cgo LDFLAGS:-L/usr/lib/x86_64-linux-gnu -libssl -lcrypto
// CPP의 CIupdtSockSSL 클래스를 대체하는 struct
type CIupdtSockSSL struct{
	m_sock	int
	m_ctx	*C.struct_ssl_ctx_st
	m_ssl	*C.struct_ssl_st
	m_cert   string
	m_privkey string
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

func (s CIupdtSockSSL) _SSL_SetupCtxServer() (*C.struct_ssl_ctx_st, error) {
	var err error
	var ctx *C.struct_ssl_ctx_st

	ctx, err = s._SSL_SetupCtx()
	if err != nil {
		return ctx, err
	}
	if C.SSL_CTX_use_certificate_file(ctx, C.CString(s.m_cert), C.SSL_FILETYPE_PEM) <= 0 {
		err = errors.New("SSL_CERT_ERROR")
		log.Fatal("SSL use certificate file error")
	}
	if C.SSL_CTX_use_PrivateKey_file(ctx, C.CString(s.m_privkey), C.SSL_FILETYPE_PEM) <= 0{
		err = errors.New("SSL_CERT_ERROR")
		log.Fatal("SSL use privatekey file error")
	}

	if C.SSL_CTX_check_private_key(ctx) < 0 {
		err = errors.New("SSL_CERT_ERROR")
		log.Fatal("SSL ckeck private key error")
	}

	return ctx, nil
}

// Wrapping SSL function - 다른 파일로 이동시켜야 한다.
func SSL_CTX_new() (*C.struct_ssl_ctx_st, error) {
	var ctx *C.SSL_CTX
	ctx = C.SSL_CTX_new(C.SSLv23_method())
	if ctx == nil {
		log.Fatal("SSL ctx alloc fail")
		return nil, errors.New("SSL_CREATE_CTX_ERROR")
	}
	return ctx, nil
}
func SSL_CTX_set_cipher_list(ctx *C.struct_ssl_ctx_st, str string) error {
	ret := C.SSL_CTX_set_cipher_list(ctx, C.CString(str))
	if int(ret) == 0 {
		return errors.New("SSL_CREATE_CTX_ERROR")
	}
	return nil
}
func SSL_new(ctx *C.struct_ssl_ctx_st) (*C.struct_ssl_st, error) {
	ssl := C.SSL_new(ctx)
	if ssl == nil {
		return nil, errors.New("SSL_ACCEPT_FAIL")
	}
	return ssl, nil
}

func (s CIupdtSockSSL) _SSL_SetupCtx() (*C.struct_ssl_ctx_st, error) {
	var err error
	var ctx *C.struct_ssl_ctx_st
	var t syscall.Time_t
	syscall.Time(&t)
	ctx, err = SSL_CTX_new()
	if err != nil {
		C.SSL_CTX_free(ctx)
		return nil, err
	}
	err = SSL_CTX_set_cipher_list(ctx, "ALL")
	if err != nil {
		C.SSL_CTX_free(ctx)
		return nil, err
	}
	return ctx, nil
}

func (s CIupdtSockSSL) _SSL_Init() {
	return
}

func (s CIupdtSockSSL) _SSL_Free() {
	if s.m_ssl != nil {
		C.SSL_free(s.m_ssl)
		s.m_ssl = nil
	}
	if s.m_ctx != nil {
		C.SSL_CTX_free(s.m_ctx)
		s.m_ctx = nil
	}
}

func (s CIupdtSockSSL) _SSL_GetError(code int) (int, error) {
	err := C.SSL_get_error(s.m_ssl, C.const_long(code))

	// TODO : switch-case
	if err == SSL.SSL_ERROR_NONE {
		return int(err), errors.New("_")
	}

	return 0, nil
}

func (s CIupdtSockSSL) SSL_Accept(sockfd int) error {
	var err error
	s.m_sock = sockfd
	ling := syscall.Linger{Onoff: 1, Linger: 0}
	syscall.SetsockoptLinger(s.m_sock, syscall.SOL_SOCKET, syscall.SO_LINGER, &ling)
	s.m_ctx, err = s._SSL_SetupCtxServer()
	if err != nil {
		log.Fatal("SSL set cipher list fail")
		return err
	}

	s.m_ssl, err = SSL_new(s.m_ctx)
	if err != nil {
		log.Fatal("SSL cannot create ssl object")
		return err
	}

	C.SSL_set_fd(s.m_ssl, C.int(s.m_sock))
	// SSL_set_mode(m_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);
	// C.SSL_ctrl(s.m_ssl, 33, C.long(0x00000001) | C.long(0x00000002) | C.long(0x00000004), nil)
	C.SSL_ctrl(s.m_ssl, 33, SSL.SSL_MODE_ENABLE_PARTIAL_WRITE | SSL.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL.SSL_MODE_AUTO_RETRY, nil)

	if int(C.SSL_accept(s.m_ssl)) != 1 {
		err = errors.New("SSL_ACCEPT_FAIL")
		log.Fatal("SSL accept error")
		return err
	}

	return nil
}

func (s CIupdtSockSSL) _SSL_Connect() error {
	var err error
	s.m_ctx, err = s._SSL_SetupCtx()
	if err != nil {
		log.Fatal("SSL cannot setup context")
		s._SSL_Free()
		return errors.New("SSL_CONNECT_FAIL")
	}
	s.m_ssl, err = C.SSL_new(s.m_ctx)
	if err != nil {
		log.Fatal("SSL cannot create ssl object")
		s._SSL_Free()
		return errors.New("SSL_CONNECT_FAIL")
	}

	C.SSL_set_fd(s.m_ssl, s.m_sock)
	C.SSL_set_mode(s.m_ssl, SSL.SSL_MODE_ENABLE_PARTIAL_WRITE |
							SSL.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
							SSL.SSL_MODE_AUTO_RETRY)
	ret := C.SSL_connect(s.m_ssl)

	if ret != C.int(1) {
		ret, err = s._SSL_GetError()
		// TODO : Fill here
	}
	curCipr := C.GoString(C.SSL_CIPHER_get_name(C.SSL_get_current_cipher(s.m_ssl)))
	fmt.Println("SSL connection is success. current cipher name : " + curCipr)
	// TODO : call log writer
	return nil
}

func (s CIupdtSockSSL) Send(buf unsafe.Pointer, size uint16) error {
	if s.m_sock < 0 || buf == nil || size > 0 {
		log.Fatal("check input value")
		return errors.New("INVALID_INPUT")
	}

	var sentLen uint16
	var ret int16
	var err error

	sentLen = 0
	ret = 0

	for sentLen < size {
		ret = C.SSL_write(s.m_ssl, C.CString((*C.uchar)(buf)+sentLen), C.uint(size - sentLen))
		if ret < 1 {
			ret, err = s._SSL_GetError()
		}
	}

}

func main() {
	mysock := CIupdtSockSSL{0, nil, nil, "", ""}
	C._SSL_Init_Wrap()
	mysock.Connect("127.0.0.1", 80, 1.0)
}