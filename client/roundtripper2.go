package client

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	"github.com/spacemonkeygo/openssl"
)

type RoundTripper2 struct {
	client     *Client
	credential *Credential
}

func (rt *RoundTripper2) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			// we explicitly don't use an proxy
			return nil, nil
		},
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		DialTLS: func(network, addr string) (net.Conn, error) {
			ctx, err := openssl.NewCtx()
			if err != nil {
				return nil, fmt.Errorf("Error creating openssl ctx: %s", err.Error())
			}

			ctx.SetCipherList(strings.Join([]string{
				"ECDHE-ECDSA-AES128-GCM-SHA256",
				"ECDHE-RSA-AES128-GCM-SHA256",
				"ECDHE-ECDSA-AES256-GCM-SHA384",
				"ECDHE-RSA-AES256-GCM-SHA384",
				"DHE-RSA-AES128-GCM-SHA256",
				"DHE-DSS-AES128-GCM-SHA256",
				"DHE-RSA-AES256-GCM-SHA384",
				"DHE-DSS-AES256-GCM-SHA384",
				"ECDHE-ECDSA-AES128-SHA256",
				"ECDHE-RSA-AES128-SHA256",
				"ECDHE-ECDSA-AES128-SHA",
				"ECDHE-RSA-AES128-SHA",
				"ECDHE-ECDSA-AES256-SHA384",
				"ECDHE-RSA-AES256-SHA384",
				"ECDHE-ECDSA-AES256-SHA",
				"ECDHE-RSA-AES256-SHA",
				"DHE-RSA-AES128-SHA256",
				"DHE-RSA-AES256-SHA256",
				"DHE-RSA-AES128-SHA",
				"DHE-RSA-AES256-SHA",
				"DHE-DSS-AES128-SHA256",
				"DHE-DSS-AES256-SHA256",
				"DHE-DSS-AES128-SHA",
				"DHE-DSS-AES256-SHA",
				"AES128-GCM-SHA256",
				"AES256-GCM-SHA384",
				"AES128-SHA256",
				"AES256-SHA256",
				"AES128-SHA",
				"AES256-SHA",
			}, ":"))

			ctx.UseCertificate(rt.credential.Certificate)
			ctx.UsePrivateKey(rt.credential.PrivateKey)

			ctx.SetSessionCacheMode(openssl.SessionCacheClient)

			ctx.SetSessionId([]byte{1})

			if keytalkPath, err := KeytalkPath(); err != nil {
				return nil, err
			} else if err := ctx.LoadVerifyLocations(path.Join(keytalkPath, "ca-bundle.pem"), ""); err != nil {
				return nil, fmt.Errorf("Error loading verify locations: %s", err.Error())
			}

			ctx.SetVerifyMode(openssl.VerifyPeer)

			conn, err := openssl.Dial(network, addr, ctx, openssl.InsecureSkipHostVerification)
			if err != nil {
				return nil, fmt.Errorf("Error dialing: %s", err.Error())
			}

			host, _, err := net.SplitHostPort(addr)
			if err = conn.SetTlsExtHostName(host); err != nil {
				return nil, fmt.Errorf("Error set tls ext host: %s", err.Error())
			}

			conn.SetDeadline(time.Now().Add(time.Minute * 10))

			err = conn.Handshake()
			if err != nil {
				return nil, fmt.Errorf("Error handshake host: %s", err.Error())
			}

			return conn, err
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if resp, err := transport.RoundTrip(req); err != nil {
		log.Error(err.Error())

		fmt.Println(color.RedString(fmt.Sprintf("[+] Error roundtrip: %s", err.Error())))

		r, w := io.Pipe()
		resp := &http.Response{
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       r,
			Request:    req,
		}

		prw := &pipeResponseWriter{r, w, resp, nil}
		go func() {
			prw.WriteHeader(500)
			prw.Write([]byte(fmt.Sprintf("Error: %s", err.Error())))
			w.Close()
		}()
		return resp, nil

	} else {
		return resp, err
	}
}
