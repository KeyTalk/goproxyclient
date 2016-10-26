package client

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"

	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	"github.com/gorilla/mux"
	keytalk "github.com/keytalk/libkeytalk/client"
	"github.com/keytalk/libkeytalk/rccd"
	"github.com/mitchellh/go-homedir"
	"github.com/spacemonkeygo/openssl"
)

type RoundTripper struct {
	client   *Client
	rccd     *rccd.RCCD
	provider *rccd.Provider
	service  *rccd.Service
}

func replaceInKeystore(uc *keytalk.UserCertificate) error {
	if home, err := homedir.Dir(); err != nil {
		return err
	} else if err == nil {
		loginKeychain := path.Join(home, "Library", "Keychains", "login.keychain")

		commonName := uc.Subject.CommonName

		cmd := exec.Command("/usr/bin/security", "delete-certificate", "-k", loginKeychain, "-c", commonName)
		if err := cmd.Run(); err != nil {
			return err
		}

		tmpfile, err := ioutil.TempFile("", "keytalk")
		if err != nil {
			return err
		}

		defer os.Remove(tmpfile.Name())

		key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(uc.PrivateKey().(*rsa.PrivateKey))}

		if err := pem.Encode(tmpfile, key); err != nil {
			return err
		}

		if err := tmpfile.Close(); err != nil {
			return err
		}

		cmd = exec.Command("/usr/bin/security", "add-certificates", "-k", loginKeychain, tmpfile.Name())
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	return nil
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
		router.PathPrefix("/logo.png").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "image/png")
			w.WriteHeader(200)

			w.Write(rt.rccd.Logo)
		})

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
						message = fmt.Sprintf("Error authenticating with Keytalk: %s", err.Error())
						break
					}

					username = r.PostFormValue("username")
					password = r.PostFormValue("password")

					if uc, err := kc.Authenticate(username, password, rt.service.Name); err != nil {
						log.Error("Error authenticating with Keytalk: %s", err.Error())
						message = fmt.Sprintf("Error authenticating with Keytalk: %s", err.Error())
						fmt.Println(color.RedString(fmt.Sprintf("[+] Error retrieving certificate from %s: %s.", rt.provider.Server, err.Error())))
						break
					} else {
						fmt.Println(color.YellowString(fmt.Sprintf("[+] Short lived certificate received from %s, valid till %s.", rt.provider.Server, uc.NotAfter)))

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
							NotBefore:   uc.NotBefore,
							NotAfter:    uc.NotAfter,
						}

						w.Header().Set("Connection", "close")

						replaceInKeystore(uc)

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

		router.ServeHTTP(prw, req)
	}()

	<-ready

	return resp, nil
}
