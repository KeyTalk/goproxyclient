# goproxyclient

The goproxyclient is the engine of the KeyTalk Proxy Client.

## Install

### Install Golang

If you do not have a working Golang environment setup please follow Golang Installation Guide.

### Install KeyTalk goproxyclient

```bash
$ go get github.com/KeyTalk/goproxyclient

$ go generate bindata/bindata.go
$ CGO_CFLAGS="-I$(pwd)/openssl-1.0.2j/include/" CGO_LDFLAGS="-L$(pwd)/openssl-1.0.2j/" go build -o bin/keytalk-proxy -ldflags=-s
```
