package main

import (
	"flag"
	"io"
	"os"
	"runtime"

	client "github.com/keytalk/client/client"

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

	var config client.Config
	if _, err := toml.DecodeFile(configFile, &config); err != nil {
		panic(err)
	}

	logBackends := []logging.Backend{}
	for _, log := range config.Logging {
		var err error

		var output io.Writer = os.Stdout
		switch log.Output {
		case "stdout":
		case "stderr":
			output = os.Stderr
		default:
			output, err = os.OpenFile(log.Output, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		}

		if err != nil {
			panic(err)
		}

		backend1 := logging.NewLogBackend(output, "", 0)
		backend1Leveled := logging.AddModuleLevel(backend1)

		level, err := logging.LogLevel(log.Level)
		if err != nil {
			panic(err)
		}

		backend1Leveled.SetLevel(level, "")
		backend1Formatter := logging.NewBackendFormatter(backend1Leveled, format)

		logBackends = append(logBackends, backend1Formatter)
	}

	logging.SetBackend(logBackends...)

	var c *client.Client
	if v, err := client.New(&config); err != nil {
		panic(err)
	} else {
		c = v
	}

	c.ListenAndServe()
}
