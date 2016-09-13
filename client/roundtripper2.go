package client

import (
	"net"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/spacemonkeygo/openssl"
)

type RoundTripper2 struct {
	client     *Client
	credential *Credential
}

func (rt *RoundTripper2) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		DialTLS: func(network, addr string) (net.Conn, error) {
			ctx, err := openssl.NewCtx()
			if err != nil {
				log.Error("Error creating openssl ctx: %s", err.Error())
				return nil, err
			}

			ctx.UseCertificate(rt.credential.Certificate)
			ctx.UsePrivateKey(rt.credential.PrivateKey)

			ctx.SetSessionCacheMode(openssl.SessionCacheClient)

			ctx.SetSessionId([]byte{1})

			// todo(nl5887): change verify mode
			ctx.SetVerifyMode(openssl.VerifyNone)

			conn, err := openssl.Dial(network, addr, ctx, openssl.InsecureSkipHostVerification)
			if err != nil {
				log.Error("Error dialing: %s", err.Error())
				return nil, err
			}

			host, _, err := net.SplitHostPort(addr)
			if err = conn.SetTlsExtHostName(host); err != nil {
				log.Error("Error set tls ext host: %s", err.Error())
				return nil, err
			}

			conn.SetDeadline(time.Now().Add(time.Minute * 10))

			err = conn.Handshake()
			if err != nil {
				log.Error("Error handshake: %s", err.Error())
				return nil, err
			}
			return conn, err
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return transport.RoundTrip(req)
}
