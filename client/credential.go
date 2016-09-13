package client

import "github.com/spacemonkeygo/openssl"

type Credential struct {
	Certificate *openssl.Certificate
	PrivateKey  openssl.PrivateKey
}
