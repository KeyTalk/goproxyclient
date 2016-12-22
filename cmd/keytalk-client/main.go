package cmd

import (
	"flag"
	"github.com/keytalk/client"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/op/go-logging"
)

var version = "0.1"

var format = logging.MustStringFormatter(
	"%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

var log = logging.MustGetLogger("keytalk/client")

var configFile string

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.StringVar(&configFile, "config", "config.toml", "specifies the location of the config file")
}

func main() {
	flag.Parse()

	var (
		md  toml.MetaData
		err error
	)

	c := client.New()
	if md, err = toml.DecodeFile(configFile, &c); err != nil {
		panic(err)
	}

	_ = md

	c.ListenAndServe()
}
