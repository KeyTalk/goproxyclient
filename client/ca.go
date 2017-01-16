package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

func LoadCA(capath string) (tls.Certificate, error) {
	data, err := ioutil.ReadFile(capath)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(data, data)
}

func GenerateNewCA(capath string) (tls.Certificate, error) {
	var priv *rsa.PrivateKey
	if pk, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return tls.Certificate{}, err
	} else {
		priv = pk
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365 * 2)

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"KeyTalk Client CA"},
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	if serialNumber, err := rand.Int(rand.Reader, serialNumberLimit); err != nil {
		return tls.Certificate{}, err
	} else {
		template.SerialNumber = serialNumber
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	f, err := os.OpenFile(capath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer f.Close()

	var cert bytes.Buffer
	pem.Encode(io.MultiWriter(&cert, f), &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	var pk bytes.Buffer
	pem.Encode(io.MultiWriter(&pk, f), &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(cert.Bytes(), pk.Bytes())
}
