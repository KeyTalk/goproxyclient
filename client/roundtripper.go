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

	"encoding/json"
	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	"github.com/gorilla/mux"
	keytalk "github.com/keytalk/libkeytalk/client"
	"github.com/keytalk/libkeytalk/rccd"
	"github.com/mitchellh/go-homedir"
	"github.com/spacemonkeygo/openssl"
)

type Preferences struct {
	path  string
	items map[string]string
}

func (p Preferences) Get(key string) string {
	p.load()
	return p.items[key]
}

func (p Preferences) load() {
	if f, err := os.Open(p.path); err != nil {
	} else if json.NewDecoder(f).Decode(&p.items); err != nil {
	}
}

func (p Preferences) save() {
	if f, err := os.Open(p.path); err != nil {
	} else if json.NewDecoder(f).Decode(&p.items); err != nil {
	}
}

func (p Preferences) Set(key, val string) {
	p.load()
	defer p.save()

	p.items[key] = val
}

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
					fmt.Println(fingerprint, err.Error())
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
			w.WriteHeader(200)

			w.Write(rt.rccd.Logo)
		})

		router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				username = rt.client.config.Username
				password = rt.client.config.Password
				service  = rt.client.config.Service
			)

			// write service to preferences
			keytalkPath, _ := KeytalkPath()

			prefs := Preferences{
				path:  path.Join(keytalkPath, "prefs.json"),
				items: map[string]string{},
			}

			if v := prefs.Get(rt.provider.Name); v != "" {
				service = v
			}

			message := ""

			if r.Method == "POST" {
				for {
					kc, err := keytalk.New(rt.rccd, fmt.Sprintf("https://%s", rt.provider.Server))
					if err != nil {
						message = fmt.Sprintf("Error initializing Keytalk client: %s", err.Error())
						break
					}

					jar, _ := cookiejar.New(nil)

					kc.Client = &http.Client{
						Transport: &http.Transport{
							TLSClientConfig: &tls.Config{
								InsecureSkipVerify: true,
							},
							Proxy: func(*http.Request) (*url.URL, error) {
								// we explicitly don't use an proxy
								return nil, nil
							},
						},
						Jar: jar,
					}

					username = r.PostFormValue("username")
					password = r.PostFormValue("password")
					service = r.PostFormValue("service")

					if uc, err := kc.Authenticate(username, password, service); err != nil {
						message = fmt.Sprintf("Error authenticating with Keytalk: %s", err.Error())
						fmt.Println(color.RedString(fmt.Sprintf("[+] Error retrieving certificate from %s: %s.", rt.provider.Server, err.Error())))

						rt.client.hub.broadcast <- &struct {
							Type         string `json:"type"`
							ErrorMessage string `json:"error_message"`
						}{
							Type:         "error",
							ErrorMessage: err.Error(),
						}
						break
					} else {
						prefs.Set(rt.provider.Name, service)

						fmt.Println(color.YellowString(fmt.Sprintf("[+] Short lived certificate received from %s, valid till %s.", rt.provider.Server, uc.NotAfter)))

						// got certificate, store certificate
						cert2 := &pem.Block{Type: "CERTIFICATE", Bytes: uc.Raw}
						certstr := pem.EncodeToMemory(cert2)

						cert99, err := openssl.LoadCertificateFromPEM(certstr)
						if err != nil {
							log.Error("Error creating openssl ctx: %s", err.Error())
							return
						}

						key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(uc.PrivateKey().(*rsa.PrivateKey))}
						keystr := pem.EncodeToMemory(key)

						pk99, err := openssl.LoadPrivateKeyFromPEM(keystr)
						if err != nil {
							log.Error("Error creating openssl ctx: %s", err.Error())
							return
						}

						rt.client.credentials[rt.provider.Name] = &Credential{
							PrivateKey:  pk99,
							Certificate: cert99,
							NotBefore:   uc.NotBefore,
							NotAfter:    uc.NotAfter,
						}

						rt.client.hub.broadcast <- &struct {
							Type       string `json:"type"`
							PrivateKey []byte `json:"private_key"`
							PublicKey  []byte `json:"public_key"`
						}{
							Type:       "user_certificate",
							PrivateKey: keystr,
							PublicKey:  certstr,
						}

						if err := replaceInKeystore(uc); err != nil {
							log.Error("Could not load certificate in keychain: %s", err.Error())
						}

						w.Header().Set("Connection", "close")
						w.Header().Set("Location", r.URL.String())
						w.WriteHeader(http.StatusFound)
						return
					}

					break
				}
			}

			services := []rccd.Service{}
			for _, service := range rt.provider.Services {
				services = append(services, service)
			}

			if err := rt.client.template.Execute(w, map[string]interface{}{
				"username": username,
				"password": password,
				"message":  message,
				"service":  rt.service,
				"provider": rt.provider,
				"services": services,
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
