package client

import (
	"errors"
	"time"

	"github.com/spacemonkeygo/openssl"
)

var (
	ErrCredentialExpired = errors.New("Certificate has expired.")
)

type Credential struct {
	Certificate *openssl.Certificate
	PrivateKey  openssl.PrivateKey

	NotBefore time.Time
	NotAfter  time.Time
}

func (credential *Credential) Valid() error {
	if time.Now().After(credential.NotAfter) {
		return ErrCredentialExpired
	}

	return nil
}
