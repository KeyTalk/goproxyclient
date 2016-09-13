package client

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
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

			ctx.UseCertificate(rt.credential.Certificate)
			ctx.UsePrivateKey(rt.credential.PrivateKey)

			ctx.SetSessionCacheMode(openssl.SessionCacheClient)

			ctx.SetSessionId([]byte{1})

			if err := ctx.LoadVerifyLocations("", path.Join(rt.client.keytalkPath, "certs")); err != nil {
				return nil, fmt.Errorf("Error loading verify locations: %s", err.Error())
			}

			// todo(nl5887): fix
			ctx.SetVerifyMode(openssl.VerifyNone)

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

			fmt.Println(conn.VerifyResult())

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
