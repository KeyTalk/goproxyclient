package client

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path"

	"github.com/elazarl/goproxy"
	"github.com/gorilla/mux"
	keytalk "github.com/keytalk/libkeytalk/client"
	"github.com/keytalk/libkeytalk/rccd"
	"github.com/mitchellh/go-homedir"
	"github.com/spacemonkeygo/openssl"
	"time"
)

type RoundTripper struct {
	client   *Client
	rccd     *rccd.RCCD
	provider *rccd.Provider
	service  *rccd.Service
}

func FingerprintString(f []byte) string {
	var buf bytes.Buffer
	for _, b := range f {
		fmt.Fprintf(&buf, "%02x", b)
	}
	return buf.String()
}

func replaceInKeystore(uc *keytalk.UserCertificate) error {
	if home, err := homedir.Dir(); err != nil {
		return err
	} else if err == nil {
		loginKeychain := path.Join(home, "Library", "Keychains", "login.keychain")

		pool := NewCertPool()

		cmd := exec.Command("/usr/bin/security", "find-certificate", "-p", "-a", loginKeychain)
		if output, err := cmd.Output(); err != nil {
			log.Info("Could not retrieve output", err.Error())
		} else if ok := pool.AppendCertsFromPEM([]byte(output)); !ok {
			log.Info("Could not parse find-certificate output", string(output))
		} else {
			for _, cert := range pool.Certs() {
				if cert.Issuer.CommonName != "KeyTalk Signing CA" {
					continue
				}

				h := sha1.New()
				h.Write(cert.Raw)

				fingerprint := FingerprintString(h.Sum(nil))

				cmd = exec.Command("/usr/bin/security", "delete-certificate", "-Z", fingerprint, loginKeychain)
				if err := cmd.Run(); err != nil {
					log.Errorf("Error deleting certificate with fingerprint: %s: %s", fingerprint, err.Error())
				}
			}
		}

		tmpfile, err := ioutil.TempFile("", "keytalk")
		if err != nil {
			return err
		}

		defer os.Remove(tmpfile.Name())
		defer os.Remove(fmt.Sprintf("%s.p12", tmpfile.Name()))

		cert2 := &pem.Block{Type: "CERTIFICATE", Bytes: uc.Raw}
		if err := pem.Encode(tmpfile, cert2); err != nil {
			return err
		}

		key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(uc.PrivateKey().(*rsa.PrivateKey))}
		if err := pem.Encode(tmpfile, key); err != nil {
			return err
		}

		if err := tmpfile.Close(); err != nil {
			return err
		}

		cmd = exec.Command("openssl", "pkcs12", "-export", "-clcerts", "-in", tmpfile.Name(), "-out", fmt.Sprintf("%s.p12", tmpfile.Name()), "-passout", "pass:test")
		if err := cmd.Run(); err != nil {
			return err
		}

		cmd = exec.Command("/usr/bin/security", "import", fmt.Sprintf("%s.p12", tmpfile.Name()), "-k", loginKeychain, "-Ptest")
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
			w.WriteHeader(http.StatusOK)

			w.Write(rt.rccd.Logo)
		})

		router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				username = rt.client.config.Username
				password = rt.client.config.Password
				service  = rt.client.config.Service
				prompt   = ""
				message  = ""
				token    = ""
			)

			prefs := rt.client.Preferences
			defer prefs.Sync()

			if v, ok := prefs.Get(fmt.Sprintf("%s/default-service", rt.provider.Name)); ok {
				service = v.(string)
			}

			defer r.Body.Close()

			for {
				kc, err := keytalk.New(rt.rccd, fmt.Sprintf("https://%s", rt.provider.Server))
				if err != nil {
					message = fmt.Sprintf("Error initializing Keytalk client: %s", err.Error())
					log.Errorf("Error initializing Keytalk client: %s", err.Error())
					break
				}

				jar, _ := cookiejar.New(nil)

				RootCAs := x509.NewCertPool()
				RootCAs.AddCert(rt.rccd.SCA)
				RootCAs.AddCert(rt.rccd.UCA)
				RootCAs.AddCert(rt.rccd.PCA)

				kc.Client = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: false,
							RootCAs:            RootCAs,
						},
						Proxy: func(*http.Request) (*url.URL, error) {
							// we explicitly don't use an proxy
							return nil, nil
						},
					},
					Jar: jar,
				}

				if service == "" {
					service = r.FormValue("service")
				}

				if service == "" {
					service = rt.provider.Services[0].Name
				}

				token = r.FormValue("token")
				if token == "" {
					if err := kc.Hello(); err != nil {
						message = fmt.Sprintf("Error initializing Keytalk client: %s", err.Error())
						log.Errorf("Error initializing Keytalk client: %s", err.Error())
						break
					}

					if err := kc.Handshake(); err != nil {
						message = fmt.Sprintf("Error initializing Keytalk client: %s", err.Error())
						log.Errorf("Error initializing Keytalk client: %s", err.Error())
						break
					}

					token = kc.Token()
				} else {
					kc.SetToken(token)
				}

				if requirements, err := kc.Requirements(service); err != nil {
					message = fmt.Sprintf("Error retrieving requirements for service: %s: %s", service, err.Error())
					log.Errorf("Error retrieving requirements for service: %s: %s", service, err.Error())
					break
				} else {
					prompt = requirements.Prompt
				}

				if v := r.FormValue("username"); v != "" {
					username = r.FormValue("username")
				}

				if r.Method == "POST" {
					prefs.Set(fmt.Sprintf("%s/default-service", rt.provider.Name), service)

					if result, err := kc.Authenticate(username, r.PostFormValue("password"), service); err != nil {
						message = fmt.Sprintf("Error authenticating with Keytalk: %s", err.Error())
						log.Errorf("Error authenticating with Keytalk for: %s: %s", rt.provider.Server, err.Error())

						rt.client.hub.Broadcast(&struct {
							Type         string `json:"type"`
							ErrorMessage string `json:"error_message"`
						}{
							Type:         "error",
							ErrorMessage: err.Error(),
						})

						break
					} else if len(result.Challenges) > 0 {
						prompt = result.Challenges[0].Value
						password = ""
					} else {
						// finally close connection
						defer kc.Close()

						opts := []keytalk.OptionFunc{}
						if v, ok := prefs.Get(fmt.Sprintf("%s/last-messages", rt.provider.Name)); !ok {
						} else if t, err := time.Parse(time.RFC3339, v.(string)); err != nil {
							log.Errorf("Could not parse time: %s", err.Error())
						} else {
							opts = append(opts, keytalk.OptTime(t))
						}

						if messages, err := kc.LastMessages(opts...); err == nil {
							for _, message := range messages {
								if message.Text == "" {
									continue
								}

								rt.client.hub.Broadcast(&struct {
									Type string `json:"type"`
									Text string `json:"text"`
								}{
									Type: "message",
									Text: message.Text,
								})
							}

							prefs.Set(fmt.Sprintf("%s/last-messages", rt.provider.Name), time.Now().Format(time.RFC3339))
						} else {
							log.Errorf("Error retrieving messages: %s", err)
						}

						log.Infof("Short lived certificate received from %s, valid till %s.", rt.provider.Server, result.NotAfter)

						// got certificate, store certificate
						cert2 := &pem.Block{Type: "CERTIFICATE", Bytes: result.Raw}
						certstr := pem.EncodeToMemory(cert2)

						cert99, err := openssl.LoadCertificateFromPEM(certstr)
						if err != nil {
							log.Errorf("Error creating openssl ctx: %s", err.Error())
							return
						}

						key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(result.PrivateKey().(*rsa.PrivateKey))}
						keystr := pem.EncodeToMemory(key)

						pk99, err := openssl.LoadPrivateKeyFromPEM(keystr)
						if err != nil {
							log.Errorf("Error creating openssl ctx: %s", err.Error())
							return
						}

						rt.client.credentials[rt.provider.Name] = &Credential{
							PrivateKey:  pk99,
							Certificate: cert99,
							ServiceURIs: result.ServiceURIs,
							NotBefore:   result.NotBefore,
							NotAfter:    result.NotAfter,
						}

						rt.client.hub.Broadcast(&struct {
							Type       string `json:"type"`
							Provider   string `json:"provider"`
							Service    string `json:"service"`
							PrivateKey []byte `json:"private_key"`
							PublicKey  []byte `json:"public_key"`
						}{
							Type:       "user_certificate",
							Provider:   rt.provider.Name,
							Service:    service,
							PrivateKey: keystr,
							PublicKey:  certstr,
						})

						if err := replaceInKeystore(result.UserCertificate); err != nil {
							log.Errorf("Could not load certificate in keychain: %s", err.Error())
						}

						w.Header().Set("Connection", "close")

						prefs.Set(fmt.Sprintf("%s/%s/service-uris", rt.provider.Name, service), result.ServiceURIs)

						if len(result.ServiceURIs) > 0 {
							log.Infof("Using service uri: %s for service: %s", result.ServiceURIs[0], service)
							w.Header().Set("Location", result.ServiceURIs[0])
						} else {
							w.Header().Set("Location", r.URL.String())
						}

						w.WriteHeader(http.StatusFound)
						return
					}
				}
				break
			}

			services := []rccd.Service{}
			for _, service := range rt.provider.Services {
				services = append(services, service)
			}

			if err := rt.client.template.Execute(w, map[string]interface{}{
				"username": username,
				"password": password,
				"token":    token,
				"prompt":   prompt,
				"message":  message,
				"service":  service,
				"provider": rt.provider,
				"services": services,
			}); err != nil {
				log.Errorf("Error executing template: %s", err.Error())
				return
			}
		})

		router.ServeHTTP(prw, req)
	}()

	<-ready

	return resp, nil
}
