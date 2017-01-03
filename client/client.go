package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/op/go-logging"

	glob "github.com/ryanuber/go-glob"

	"github.com/keytalk/client/bindata"
	rccd "github.com/keytalk/libkeytalk/rccd"

	"github.com/elazarl/goproxy"
	"runtime/debug"
)

var log = logging.MustGetLogger("keytalk/client")

type Client struct {
	listener net.Listener

	template *template.Template
	rccds    []*rccd.RCCD

	config *Config

	tlsconfig *tls.Config
	ca        *tls.Certificate

	hub *Hub

	credentials map[string]*Credential
}

func KeytalkPath() (string, error) {
	if usr, err := user.Current(); err != nil {
		return "", err
	} else {
		keytalkPath := path.Join(usr.HomeDir, "Library", "Keytalk")
		if _, err := os.Stat(keytalkPath); err == nil {
		} else if !os.IsNotExist(err) {
			return "", err
		} else if err = os.Mkdir(keytalkPath, 0700); err != nil {
			return "", err
		}

		return keytalkPath, nil
	}
}

func CachePath() (string, error) {
	if keytalkPath, err := KeytalkPath(); err != nil {
		return "", err
	} else {
		cachePath := path.Join(keytalkPath, "cache")
		if _, err := os.Stat(cachePath); err == nil {
		} else if !os.IsNotExist(err) {
			return "", err
		} else if err = os.Mkdir(cachePath, 0700); err != nil {
			return "", err
		}

		return cachePath, nil
	}
}

func New(config *Config) (*Client, error) {
	client := Client{
		rccds:  []*rccd.RCCD{},
		config: config,

		hub: newHub(),

		credentials: map[string]*Credential{},
	}

	str := ""
	if b, err := bindata.StaticIndexHtmlBytes(); err != nil {
		panic(err)
	} else {
		str = string(b)
	}

	if t, err := template.New("index.html").Parse(str); err != nil {
		return nil, err
	} else {
		client.template = t
	}

	if keytalkPath, err := KeytalkPath(); err != nil {
		return nil, err
	} else if err := client.loadRCCDs(keytalkPath); err != nil {
		return nil, err
	}

	if keytalkPath, err := KeytalkPath(); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Could retrieve keytalk path: %s.", err.Error())))
		return nil, err
	} else if cert, err := LoadCA(path.Join(keytalkPath, "ca.pem")); err == nil {
		client.ca = &cert
	} else {
		return nil, err
	}

	return &client, nil
}

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha1.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	return h.Sum(nil)
}

func hashSortedBigInt(lst []string) *big.Int {
	rv := new(big.Int)
	rv.SetBytes(hashSorted(lst))
	return rv
}

var goproxySignerVersion = ":ktproxy"

func signHost(ca tls.Certificate, hosts []string) (cert tls.Certificate, err error) {
	var x509ca *x509.Certificate
	// Use the provided ca and not the global GoproxyCa for certificate generation.
	if x509ca, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return
	}

	// todo(nl5887): we could change this to 24 hour
	start := time.Now()
	end := start.Add(time.Hour * 24 * 365)

	hash := hashSorted(append(hosts, goproxySignerVersion, ":"+runtime.Version()+":"+time.Now().Format("RFC3339")))
	serial := new(big.Int)
	serial.SetBytes(hash)

	template := x509.Certificate{
		// TODO(elazar): instead of this ugly hack, just encode the certificate and hash the binary form.
		SerialNumber: serial,
		Issuer:       x509ca.Subject,
		Subject: pkix.Name{
			Organization: []string{"Keytalk Client Certificate"},
		},
		NotBefore: start,
		NotAfter:  end,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	var certpriv *rsa.PrivateKey
	if certpriv, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, x509ca, &certpriv.PublicKey, ca.PrivateKey); err != nil {
		return
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes, ca.Certificate[0]},
		PrivateKey:  certpriv,
	}, nil
}

func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}

func (client *Client) TLSConfigFromCA(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	var config = &tls.Config{
		InsecureSkipVerify: false,
	}

	log.Debugf("Signing certificate for host %s", stripPort(host))

	if cachePath, err := CachePath(); err != nil {
		return nil, err
	} else {
		certPath := path.Join(cachePath, stripPort(host)+".pem")

		if data, err := ioutil.ReadFile(certPath); os.IsNotExist(err) {
			if cert, err := signHost(*client.ca, []string{stripPort(host)}); err != nil {
				log.Errorf("Cannot sign host certificate with provided CA: %s.", err)
				return nil, err
			} else if f, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
				return nil, err
			} else {
				defer f.Close()

				pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
				pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey))})

				config.Certificates = append(config.Certificates, cert)
			}
		} else if err != nil {
			return nil, err
		} else if cert, err := tls.X509KeyPair(data, data); err != nil {
			return nil, err
		} else {
			config.Certificates = append(config.Certificates, cert)
		}

		return config, nil
	}
}

func (client *Client) reloadRCCDs() error {
	client.rccds = []*rccd.RCCD{}
	if keytalkPath, err := KeytalkPath(); err != nil {
		return err
	} else if err := client.loadRCCDs(keytalkPath); err != nil {
		return err
	} else {
		log.Info("Reloaded RCCDs.")
		return nil
	}
}

func (client *Client) loadRCCDs(path string) error {
	return filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		if !glob.Glob("*.rccd", strings.ToLower(filepath.Base(path))) {
			return nil
		}

		log.Infof("Loading RCCD %s.", path)
		if rccd, err := rccd.Open(path); err != nil {
			return err
		} else {
			client.rccds = append(client.rccds, rccd)
		}

		return nil
	})
}

func (client *Client) serveWs(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("Error upgrading websocket connection: %s", err.Error())
		return
	}

	_ = ws

	log.Debug("Connection upgraded.")
	defer log.Debug("Connection closed")

	c := &connection{send: make(chan interface{}, 256), ws: ws, client: client}
	client.hub.register <- c

	go c.writePump()
	c.readPump()
}

func (client *Client) deleteCertificate() {
	log.Info("Deleting user certificates.")
	client.credentials = map[string]*Credential{}
}

func (client *Client) ListenAndServe() {
	log.Infof("Keytalk client started.")
	defer log.Infof("Keytalk client stopped.")

	defer func() {
		if err := recover(); err != nil {
			log.Criticalf("Panic: %s\nStacktrace:\n%s\n", err, string(debug.Stack()))
			os.Exit(1)
		}
	}()

	proxy := goproxy.NewProxyHttpServer()

	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		for _, rccd := range client.rccds {
			for _, provider := range rccd.Providers {
				for _, service := range provider.Services {
					if u, err := url.Parse(service.Uri); err != nil {
						continue
					} else if u.Host != req.Host {
						continue
					}

					if credential, ok := client.credentials[provider.Name]; !ok {
						ctx.RoundTripper = &RoundTripper{
							rccd:     rccd,
							provider: &provider,
							service:  &service,
							client:   client,
						}
					} else if err := credential.Valid(); err != nil {
						ctx.RoundTripper = &RoundTripper{
							rccd:     rccd,
							provider: &provider,
							service:  &service,
							client:   client,
						}
					} else {
						log.Infof("Found valid credential for %s.", req.Host)

						ctx.RoundTripper = &RoundTripper2{
							client:     client,
							credential: credential,
						}
					}
				}
			}
		}

		for _, credential := range client.credentials {
			for _, serviceURI := range credential.ServiceURIs {
				if u, err := url.Parse(serviceURI); err != nil {
					continue
				} else if u.Host != req.Host {
					continue
				}

				if err := credential.Valid(); err != nil {
					log.Errorf("Could not find valid credentials for %s.", req.Host)
				} else {
					log.Infof("Found valid credential for %s.", req.Host)
					ctx.RoundTripper = &RoundTripper2{
						client:     client,
						credential: credential,
					}
				}
			}
		}

		return req, nil
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		return resp
	})

	proxy.OnRequest().
		HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			if h, _, err := net.SplitHostPort(host); err != nil {
				return goproxy.OkConnect, host
			} else {
				for _, rccd := range client.rccds {
					for _, provider := range rccd.Providers {
						for _, service := range provider.Services {
							if u, err := url.Parse(service.Uri); err != nil {
								continue
							} else if u.Host != h {
								continue
							}

							log.Infof("Found service %s for uri %s.", service.Name, service.Uri)

							return &goproxy.ConnectAction{
								Action:    goproxy.ConnectMitm,
								TLSConfig: client.TLSConfigFromCA,
							}, host
						}
					}
				}

				for k, credential := range client.credentials {
					for _, serviceURI := range credential.ServiceURIs {
						if u, err := url.Parse(serviceURI); err != nil {
							continue
						} else if u.Host != h {
							continue
						}

						log.Infof("Found service %s for uri %s.", k, serviceURI)

						return &goproxy.ConnectAction{
							Action:    goproxy.ConnectMitm,
							TLSConfig: client.TLSConfigFromCA,
						}, host
					}
				}
			}

			return goproxy.OkConnect, host
		}))

	proxy.Verbose = false

	go client.hub.run()

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/ws" {
			client.serveWs(w, req)
			return
		}

		http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", 500)
	})

	if err := http.ListenAndServe(client.config.ListenerString, proxy); err != nil {
		panic(err)
	}
}
