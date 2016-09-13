package client

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/gorilla/mux"
	keytalk "github.com/keytalk/libkeytalk/client"
	"github.com/keytalk/libkeytalk/rccd"
	"github.com/spacemonkeygo/openssl"
)

type RoundTripper struct {
	client   *Client
	rccd     *rccd.RCCD
	provider *rccd.Provider
	service  *rccd.Service
}

func (rt *RoundTripper) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	r, w := io.Pipe()

	resp := &http.Response{
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       r,
		Request:    req,
	}

	ready := make(chan struct{})
	prw := &pipeResponseWriter{r, w, resp, ready}
	go func() {
		defer w.Close()

		var router = mux.NewRouter()
		router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				username = rt.client.config.Username
				password = rt.client.config.Password
			)

			message := ""

			if r.Method == "POST" {
				for {
					kc, err := keytalk.New(rt.rccd, fmt.Sprintf("https://%s", rt.provider.Server))
					if err != nil {
						// todo(nl5887): return body with error
						message = fmt.Sprintf("Error authenticating with Keytalk: %s", err.Error())
						break
					}

					username = r.PostFormValue("username")
					password = r.PostFormValue("password")

					if uc, err := kc.Authenticate(username, password, rt.service.Name); err != nil {
						// todo(nl5887): return body with error
						log.Error("Error authenticating with Keytalk: %s", err.Error())
						message = fmt.Sprintf("Error authenticating with Keytalk: %s", err.Error())
						break
					} else {
						fmt.Printf("Got user certificate: %#v\n", uc)

						// got certificate, store certificate
						cert2 := &pem.Block{Type: "CERTIFICATE", Bytes: uc.Raw}
						certstr := pem.EncodeToMemory(cert2)

						cert99, err := openssl.LoadCertificateFromPEM(certstr)
						if err != nil {
							log.Error("Error creating openssl ctx: %s", err.Error())
							panic(err)
						}

						key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(uc.PrivateKey().(*rsa.PrivateKey))}
						keystr := pem.EncodeToMemory(key)

						pk99, err := openssl.LoadPrivateKeyFromPEM(keystr)
						if err != nil {
							log.Error("Error creating openssl ctx: %s", err.Error())
							panic(err)
						}

						rt.client.credentials[rt.provider.Name] = &Credential{
							PrivateKey:  pk99,
							Certificate: cert99,
						}

						w.Header().Set("Connection", "close")

						w.Header().Set("Location", r.URL.String())
						w.WriteHeader(http.StatusFound)
						return
					}

					break
				}
			}

			if err := rt.client.template.Execute(w, map[string]interface{}{
				"username": username,
				"password": password,
				"message":  message,
				"service":  rt.service,
				"provider": rt.provider,
			}); err != nil {
				log.Error("Error executing template: %s", err.Error())
				panic(err)
			}
		})

		// router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
		router.ServeHTTP(prw, req)
	}()
	<-ready

	return resp, nil
}
