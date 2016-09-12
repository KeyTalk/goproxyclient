package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
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
	"github.com/gorilla/mux"

	glob "github.com/ryanuber/go-glob"

	"github.com/spacemonkeygo/openssl"

	keytalk "github.com/keytalk/libkeytalk/client"
	rccd "github.com/keytalk/libkeytalk/rccd"

	"github.com/elazarl/goproxy"
)

// var log = logging.MustGetLogger("keytalk/client")

var loggedIn = false

type Transport struct {
}

func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	return http.DefaultTransport.RoundTrip(req)
}

type Client struct {
	listener          net.Listener
	TLSListenerString string `toml:"tlslisten"`

	CACertificateFile     string `toml:"ca_cert"`
	ServerCertificateFile string `toml:"server_cert"`
	ServerKeyFile         string `toml:"server_key"`
	AuthType              string `toml:"authenticationtype"`

	Logging []struct {
		Output string `toml:"output"`
		Level  string `toml:"level"`
	} `toml:"logging"`

	rccds []*rccd.RCCD
}

func New() *Client {
	return &Client{
		rccds: []*rccd.RCCD{},
	}
}

func (c *Client) HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("TEST"))
}

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

/*
func ServeHTTP(w http.ResponseWriter, r *http.Request) {
}
*/
type pipeResponseWriter struct {
	r     *io.PipeReader
	w     *io.PipeWriter
	resp  *http.Response
	ready chan<- struct{}
}

func (w *pipeResponseWriter) Header() http.Header {
	return w.resp.Header
}

func (w *pipeResponseWriter) Write(p []byte) (int, error) {
	if w.ready != nil {
		w.WriteHeader(http.StatusOK)
	}
	return w.w.Write(p)
}

func (w *pipeResponseWriter) WriteHeader(status int) {
	if w.ready == nil {
		// already called
		return
	}
	w.resp.StatusCode = status
	w.resp.Status = fmt.Sprintf("%d %s", status, http.StatusText(status))
	close(w.ready)
	w.ready = nil
}

type RoundTripper2 struct {
}

var (
	cert99 *openssl.Certificate
	pk99   openssl.PrivateKey
)

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

			ctx.UseCertificate(cert99)
			ctx.UsePrivateKey(pk99)

			ctx.SetSessionCacheMode(openssl.SessionCacheClient)

			ctx.SetSessionId([]byte{1})

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

type RoundTripper struct {
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
		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// should redirect to internal url.
			var (
				username string
				password string
			)

			invalid := false

			if r.Method == "POST" {
				kc, err := keytalk.New(rt.rccd, fmt.Sprintf("https://%s", rt.provider.Server))
				if err != nil {
					// todo(nl5887): return body with error
					panic(err)
					log.Error("Error initializing Keytalk client: %s", err.Error())
				}

				username = r.PostFormValue("username")
				password = r.PostFormValue("password")

				if uc, err := kc.Authenticate(username, password, rt.service.Name); err != nil {
					// todo(nl5887): return body with error
					log.Error("Error authenticating with Keytalk: %s", err.Error())
					panic(err)
				} else {
					fmt.Printf("Got user certificate: %#v\n", uc)
					// got certificate, store certificate
					cert2 := &pem.Block{Type: "CERTIFICATE", Bytes: uc.Raw}
					certstr := pem.EncodeToMemory(cert2)

					cert99, err = openssl.LoadCertificateFromPEM(certstr)
					if err != nil {
						log.Error("Error creating openssl ctx: %s", err.Error())
						panic(err)
					}

					key := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(uc.PrivateKey().(*rsa.PrivateKey))}
					keystr := pem.EncodeToMemory(key)

					pk99, err = openssl.LoadPrivateKeyFromPEM(keystr)
					if err != nil {
						log.Error("Error creating openssl ctx: %s", err.Error())
						panic(err)
					}

					loggedIn = true
					w.Header().Set("Connection", "close")

					w.Header().Set("Location", r.URL.String())
					w.WriteHeader(http.StatusFound)
					return
				}

				invalid = true
			}

			t, err := template.New("index.html").ParseFiles("./static/index.html")
			if err != nil {
				panic(err)
			}

			err = t.Execute(w, map[string]interface{}{
				"username": username,
				"password": password,
				"invalid":  invalid,
			})
			if err != nil {
				panic(err)
			}
		})

		router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
		router.ServeHTTP(prw, req)
	}()
	<-ready

	return resp, nil
}

func (c *Client) GenerateNewCA() (tls.Certificate, error) {
	var priv *rsa.PrivateKey
	if pk, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return tls.Certificate{}, err
	} else {
		priv = pk
	}

	notBefore := time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365 * 2)

	template := x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Keytalk Client CA"},
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	if serialNumber, err := rand.Int(rand.Reader, serialNumberLimit); err != nil {
		return tls.Certificate{}, err
	} else {
		template.SerialNumber = serialNumber
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var cert bytes.Buffer
	pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	var pk bytes.Buffer
	pem.Encode(&pk, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// save config
	return tls.X509KeyPair(cert.Bytes(), pk.Bytes())

	/*
		certOut, err := os.Create("cert.pem")
		if err != nil {
			log.Fatalf("failed to open cert.pem for writing: %s", err)
		}
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()
		log.Print("written cert.pem\n")

		keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Print("failed to open key.pem for writing:", err)
			return
		}
		pem.Encode(keyOut, pemBlockForKey(priv))
		keyOut.Close()
		log.Print("written key.pem\n")
	*/
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
	if certpriv, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
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

func TLSConfigFromCA(ca *tls.Certificate) func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
		config := defaultTLSConfig
		ctx.Logf("signing for %s", stripPort(host))
		cert, err := signHost(*ca, []string{stripPort(host)})
		if err != nil {
			ctx.Warnf("Cannot sign host certificate with provided CA: %s", err)
			return nil, err
		}
		config.Certificates = append(config.Certificates, cert)
		return config, nil
	}
}

func (c *Client) visit(path string, f os.FileInfo, err error) error {
	if !glob.Glob("*.rccd", strings.ToLower(filepath.Base(path))) {
		return nil
	}

	fmt.Println(color.YellowString(fmt.Sprintf("[+] Found RCCD %s.", path)))

	if rccd, err := rccd.Open(path); err != nil {
		return err
	} else {
		c.rccds = append(c.rccds, rccd)
	}

	return nil
}

func (c *Client) ListenAndServe() {
	log.Info("Starting client....")

	keytalkPath := ".keytalk"
	if usr, err := user.Current(); err != nil {
		panic(err)
	} else {
		keytalkPath = path.Join(usr.HomeDir, keytalkPath)
		if _, err := os.Stat(keytalkPath); err == nil {
		} else if !os.IsNotExist(err) {
		} else if err = os.Mkdir(keytalkPath, 0700); err != nil {
			panic(err)
		}
	}

	// todo(nl5887): first generate personal ca if not exists in cache folder
	ca, err := c.GenerateNewCA()
	if err != nil {
		panic(err)
	}

	// save all rccd's in ~/.keytalk/rccds/
	// todo(nl5887): save generated certificates to cache folder
	// todo(nl5887): arguments for starting, -c for config

	proxy := goproxy.NewProxyHttpServer()

	if err := filepath.Walk(keytalkPath, c.visit); err != nil {
		panic(err)
	}

	proxy.OnRequest().
		HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			// all services in rccd.Provider / Services
			fmt.Println(host)

			if h, _, err := net.SplitHostPort(host); err != nil {
				return goproxy.OkConnect, host
			} else {
				for _, rccd := range c.rccds {
					for _, provider := range rccd.Providers {
						for _, service := range provider.Services {
							if u, err := url.Parse(service.Uri); err != nil {
								continue
							} else if u.Host != h {
								continue
							}

							// provider is name of kt server
							// service name of service
							if loggedIn {
								ctx.RoundTripper = &RoundTripper2{}
							} else {
								ctx.RoundTripper = &RoundTripper{
									rccd:     rccd,
									provider: &provider,
									service:  &service,
								}
							}

							return &goproxy.ConnectAction{
								Action:    goproxy.ConnectMitm,
								TLSConfig: TLSConfigFromCA(&ca),
							}, host
						}
					}
				}
			}

			return goproxy.OkConnect, host
		}))

	addr := flag.String("addr", "127.0.0.1:8080", "proxy listen address")
	flag.Parse()
	proxy.Verbose = true

	// add hijack support to LogHandler
	lh := proxy // handlers.LogHandler(proxy, handlers.NewLogOptions(log.Info, "_default_"))

	if err := http.ListenAndServe(*addr, lh); err != nil {
		panic(err)
	}

}

func (c *Client) listenAndServe() {
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			log.Error("server: accept: %s", err)
			break
		}

		go c.handle(conn)
	}
}

func (c *Client) handle(conn net.Conn) {
	if err := recover(); err != nil {
		trace := make([]byte, 1024)
		count := runtime.Stack(trace, true)
		log.Error("Error: %s", err)
		log.Debug("Stack of %d bytes: %s\n", count, trace)
		return
	}

	defer conn.Close()

	tlscon, ok := conn.(*openssl.Conn)
	if !ok {
		log.Error("Could not type assert tls.Conn")
		return
	}

	defer tlscon.Close()

	reader := bufio.NewReader(tlscon)

	var req *http.Request
	var err error

	defer func() {
		if err == nil {
			return
		} else if err == io.EOF {
			return
		}

		log.Error("Error: ", err.Error())

		resp := &http.Response{
			Header:     make(http.Header),
			Request:    req,
			StatusCode: http.StatusUnauthorized,
		}

		resp.Header.Set("Server", "Keytalk Authentication Proxy")

		body := fmt.Sprintf("Keytalk proxy error: %s", err.Error())

		r := strings.NewReader(body)
		resp.Body = ioutil.NopCloser(r)

		resp.Write(tlscon)
	}()

	if err := tlscon.Handshake(); err == io.EOF {
		err = nil
		return
	} else if err != nil {
		log.Error("server: handshake failed: %s. Continuing anonymously.\n", err.Error())
		return
	}

	cert, err := tlscon.PeerCertificate()
	if err != nil {

	}

	req, err = http.ReadRequest(reader)
	if err != nil {
		return
	}

	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}

	_ = host

	commonName := ""
	if cert == nil {
		// err
		return
	}

	subject, err := cert.GetSubjectName()
	if err != nil {
		log.Error(err.Error())
		return
	}

	if s, ok := subject.GetEntry(openssl.NID_commonName); ok {
		commonName = s
	}

	_ = commonName
	return
	/*
		for {
			req.Host = backend.Host(host)

			req.URL = &url.URL{
				Scheme:   "https",
				Host:     req.Host,
				Path:     req.URL.Path,
				RawQuery: req.URL.RawQuery,
				Fragment: req.URL.Fragment,
			}

			req.Header.Del("Accept-Encoding")

			dump, _ := httputil.DumpRequest(req, false)
			log.Debug("Request: %s", string(dump))

			var resp *http.Response
			if resp, err = t.RoundTrip(req); err != nil {
				return
			}

			switch resp.StatusCode {
			case 301:
				// TODO: rewrite location urls
			case 403:
				// TODO: try to sign in again
			}

			resp.Body = NewChangeStream(resp.Body)

			dump, _ = httputil.DumpResponse(resp, false)
			if err = resp.Write(tlscon); err != nil {
				return
			}

			// TODO: add apache compatible format
			log.Info("%s %s %s %d %s %s", req.Host, req.URL.String(), req.Header.Get("Content-Type"), resp.StatusCode, commonName, req.Header.Get("Referer"))

			// for keep alive, next request
			req, err = http.ReadRequest(reader)
			if err == io.EOF {
				return
			} else if err != nil {
				return
			}
		}
	*/
}
