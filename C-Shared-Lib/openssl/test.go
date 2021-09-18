package main
import "C"
import "fmt"
/*
#cgo LDFLAGS: -lssl
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
*/
import "C"

type CIupdtSockSSL struct{
	m_sock	uint
	m_ctx	C.SSL_CTX
	m_ssl	C.SSL
	m_cert	string
	m_privkey	string
}

func (updtsock CIupdtSockSSL) Constructure() {
	updtsock.m_sock = 0
	updtsock.m_ctx	= nil
	updtsock.m_ssl	= nil

	updtsock._SSL_Init()

	fmt.Println("End constructure")
	return
}

func (updtsock CIupdtSockSSL) _SSL_Init() {
	C.SSL_library_init()
	C.SSL_load_error_strings()
	return
}

func main(){
	mysock := CIupdtSockSSL{}

	mysock.Constructure()
}