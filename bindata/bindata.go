package bindata

//go:generate go-bindata -pkg bindata -o bindata_gen.go -ignore \.map\$ ../static/...

var Prefix = "dist"
