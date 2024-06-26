package SSL

import "C"

const (
	SSL_MODE_ENABLE_PARTIAL_WRITE       = 0x00000001
	SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 0x00000002
	SSL_MODE_AUTO_RETRY                 = 0x00000004
)

const (
	// TODO : Fill this code values
	SSL_ERROR_NONE         = 0x00000001
	SSL_ERROR_ZERO_RETURN  = 0x00000001
	SSL_ERROR_WANT_READ    = 0x00000001
	SSL_ERROR_WANT_WRITE   = 0x00000001
	SSL_ERROR_WANT_CONNECT = 0x00000001
	SSL_ERROR_WANT_ACCEPT  = 0x00000001
	SSL_ERROR_SYSCALL      = 0x00000001
	SSL_ERROR_SSL          = 0x00000001
)

const (
	SSL_RECEIVED_SHUTDOWN = 2
)
