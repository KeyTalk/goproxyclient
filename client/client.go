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

	rccd "github.com/keytalk/libkeytalk/rccd"

	"github.com/elazarl/goproxy"
)

var log = logging.MustGetLogger("keytalk/client")

type Client struct {
	listener net.Listener

	template *template.Template
	rccds    []*rccd.RCCD

	config *Config

	tlsconfig *tls.Config
	ca        *tls.Certificate

	credentials map[string]*Credential

	keytalkPath string
}

func New(config *Config) (*Client, error) {
	client := Client{
		rccds:  []*rccd.RCCD{},
		config: config,

		credentials: map[string]*Credential{},
	}

	if t, err := template.New("index.html").ParseFiles("./static/index.html"); err != nil {
		return nil, err
	} else {
		client.template = t
	}

	if usr, err := user.Current(); err != nil {
		return nil, err
	} else {
		keytalkPath := path.Join(usr.HomeDir, ".keytalk")
		if _, err := os.Stat(keytalkPath); err == nil {
		} else if !os.IsNotExist(err) {
			return nil, err
		} else if err = os.Mkdir(keytalkPath, 0700); err != nil {
			return nil, err
		}

		client.keytalkPath = keytalkPath
	}

	capath := path.Join(client.keytalkPath, "ca.pem")
	if ca, err := LoadCA(capath); err == nil {
		client.ca = &ca
	} else if ca, err := GenerateNewCA(capath); err == nil {
		client.ca = &ca
	} else {
		return nil, err
	}

	if err := client.loadRCCDs(client.keytalkPath); err != nil {
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

var goproxySignerVersion = ":goroxy1"

func signHost(ca tls.Certificate, hosts []string) (cert tls.Certificate, err error) {
	var x509ca *x509.Certificate

	// Use the provided ca and not the global GoproxyCa for certificate generation.
	if x509ca, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return
	}

	// todo(nl5887): we could change this to 24 hour
	start := time.Now()
	end := start.Add(time.Hour * 24 * 365)

	hash := hashSorted(append(hosts, goproxySignerVersion, ":"+runtime.Version()))
	serial := new(big.Int)
	serial.SetBytes(hash)

	// todo(nl5887): retrieve tls certificate from dest? anduse subject name and organization of dest cert?

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

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func (client *Client) TLSConfigFromCA(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	config := defaultTLSConfig
	ctx.Logf("signing for %s", stripPort(host))

	certPath := path.Join(client.keytalkPath, "cache", stripPort(host)+".pem")

	if data, err := ioutil.ReadFile(certPath); os.IsNotExist(err) {
		if cert, err := signHost(*client.ca, []string{stripPort(host)}); err != nil {
			ctx.Warnf("Cannot sign host certificate with provided CA: %s", err)
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

func (client *Client) loadRCCDs(path string) error {
	return filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		if !glob.Glob("*.rccd", strings.ToLower(filepath.Base(path))) {
			return nil
		}

		fmt.Println(color.YellowString(fmt.Sprintf("[+] Found RCCD %s.", path)))

		if rccd, err := rccd.Open(path); err != nil {
			return err
		} else {
			client.rccds = append(client.rccds, rccd)
		}

		return nil
	})
}

func (client *Client) ListenAndServe() {
	log.Info("Starting client....")

	proxy := goproxy.NewProxyHttpServer()

	proxy.OnRequest().
		HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			// all services in rccd.Provider / Services
			fmt.Println(host)

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

							if credential, ok := client.credentials[provider.Name]; ok {
								ctx.RoundTripper = &RoundTripper2{
									client:     client,
									credential: credential,
								}
							} else {
								ctx.RoundTripper = &RoundTripper{
									rccd:     rccd,
									provider: &provider,
									service:  &service,
									client:   client,
								}
							}

							return &goproxy.ConnectAction{
								Action:    goproxy.ConnectMitm,
								TLSConfig: client.TLSConfigFromCA,
							}, host
						}
					}
				}
			}

			return goproxy.OkConnect, host
		}))

	proxy.Verbose = false

	// add hijack support to LogHandler
	lh := proxy // handlers.LogHandler(proxy, handlers.NewLogOptions(log.Info, "_default_"))

	if err := http.ListenAndServe(client.config.ListenerString, lh); err != nil {
		panic(err)
	}
}
