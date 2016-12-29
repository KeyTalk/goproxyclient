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

	"bytes"
	"encoding/json"
	"github.com/elazarl/goproxy"
	"github.com/gorilla/websocket"
)

var log = logging.MustGetLogger("keytalk/client")

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = 1 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

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

	hash := hashSorted(append(hosts, goproxySignerVersion, ":"+runtime.Version()+":"+time.Now().Format("RFC3339")))
	fmt.Println(append(hosts, goproxySignerVersion, ":"+runtime.Version()+":"+time.Now().Format("RFC3339")))
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

var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func (client *Client) TLSConfigFromCA(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	config := defaultTLSConfig
	ctx.Logf("signing for %s", stripPort(host))

	if cachePath, err := CachePath(); err != nil {
		return nil, err
	} else {
		certPath := path.Join(cachePath, stripPort(host)+".pem")

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

		log.Infof("Found RCCD %s.", path)

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

// write writes a message with the given message type and payload.
func (c *connection) write(mt int, payload []byte) error {
	c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	return c.ws.WriteMessage(mt, payload)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type connection struct {
	ws     *websocket.Conn
	send   chan interface{}
	b      int
	client *Client
}

func (c *connection) readPump() {
	defer func() {
		c.client.hub.unregister <- c
		c.ws.Close()
	}()

	c.ws.SetReadLimit(maxMessageSize)
	c.ws.SetReadDeadline(time.Now().Add(pongWait))
	c.ws.SetPongHandler(func(string) error {
		c.ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.ws.ReadMessage()
		if err == nil {
		} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
			log.Errorf("error: %v", err)
			continue
		}

		v := map[string]interface{}{}
		if err := json.NewDecoder(bytes.NewBuffer(message)).Decode(&v); err != nil {
			log.Error("error: %v", err)
			continue
		}

		if v["type"] == "reload" {
			c.client.reloadRCCDs()
		} else if v["type"] == "delete-certificate" {
			c.client.deleteCertificate()
		} else if v["type"] == "retrieve-rccds" {
			keytalkPath, _ := KeytalkPath()
			rccds := []string{}
			filepath.Walk(keytalkPath, func(path string, f os.FileInfo, err error) error {
				if !glob.Glob("*.rccd", strings.ToLower(filepath.Base(path))) {
					return nil
				}

				rccds = append(rccds, path)

				return nil
			})

			c.send <- map[string]interface{}{"type": "receive-rccds", "items": rccds}
		}
	}
}

// writePump pumps messages from the hub to the websocket connection.
func (c *connection) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.ws.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.write(websocket.CloseMessage, []byte{})
				return
			}

			buff := new(bytes.Buffer)
			if err := json.NewEncoder(buff).Encode(message); err != nil {
				log.Error(err.Error())
				return
			} else if err := c.write(websocket.BinaryMessage, buff.Bytes()); err != nil {
				log.Error(err.Error())
				return
			}
		case <-ticker.C:
			if err := c.write(websocket.PingMessage, []byte{}); err != nil {
				log.Error("%#v", err.Error())
				return
			}
		}
	}
}

func (client *Client) deleteCertificate() {
	log.Info("Deleting user certificates.")
	client.credentials = map[string]*Credential{}
}

func (client *Client) ListenAndServe() {
	fmt.Println(color.YellowString(fmt.Sprintf("[+] Keytalk client started.")))

	defer fmt.Println(color.YellowString(fmt.Sprintf("[+] Keytalk client stopped.")))

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
						ctx.RoundTripper = &RoundTripper2{
							client:     client,
							credential: credential,
						}
					}

					return req, nil
				}
			}
		}

		return req, nil
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

							fmt.Println(color.YellowString(fmt.Sprintf("[+] Found service %s for uri %s.", service.Name, service.Uri)))
							log.Infof("Found service %s for uri %s.", service.Name, service.Uri)

							return &goproxy.ConnectAction{
								Action:    goproxy.ConnectMitm,
								TLSConfig: client.TLSConfigFromCA,
							}, host
						}
					}
				}
			}
			/*
				tr := transport.Transport{Proxy: func(*http.Request) (*url.URL, error) {
					return nil, nil
				}}

				ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (resp *http.Response, err error) {
					ctx.UserData, resp, err = tr.DetailedRoundTrip(req)
					return
				})

				return &goproxy.ConnectAction{
					Action:    goproxy.ConnectAccept,
					TLSConfig: client.TLSConfigFromCA,
				}, host
			*/

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
