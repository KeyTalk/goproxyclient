go generate bindata/bindata.go
CGO_CFLAGS="-I/Users/remco/Projects/keytalk/keytalk-client/src/github.com/KeyTalk/goproxyclient/openssl-1.0.2j/include/" CGO_LDFLAGS="-L/Users/remco/Projects/keytalk/keytalk-client/src/github.com/KeyTalk/goproxyclient/openssl-1.0.2j/" go build -o bin/keytalk-proxy -ldflags=-s
#codesign -f -s "Mac Developer: Paul van Vliet (Y8EZZKZSJP)" --entitlements "./keytalk-proxy.entitlements" "bin/keytalk-proxy" # -D "bin/keytalk-proxy.signed"

