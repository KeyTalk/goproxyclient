package main

import (
	"flag"
	"io"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/keytalk/client/client"
	"github.com/minio/cli"
	"github.com/op/go-logging"
)

var version = "0.1"

var format = logging.MustStringFormatter(
	"%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}",
)

var log = logging.MustGetLogger("keytalk/client")

var globalFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "c,config",
		Usage: "config file",
		Value: "config.toml",
	},
	cli.BoolFlag{
		Name:  "help, h",
		Usage: "Show help.",
	},
}

var (
	Version = "1.0"
)

var helpTemplate = `NAME:
{{.Name}} - {{.Usage}}

DESCRIPTION:
{{.Description}}

USAGE:
{{.Name}} {{if .Flags}}[flags] {{end}}command{{if .Flags}}{{end}} [arguments...]

COMMANDS:
{{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
{{end}}{{if .Flags}}
FLAGS:
{{range .Flags}}{{.}}
{{end}}{{end}}
VERSION:
` + Version +
	`{{ "\n"}}`

var configFile string

func init() {
	flag.StringVar(&configFile, "config,c", "config.toml", "specifies the location of the config file")
}

func main() {
	// Set up app.
	app := cli.NewApp()
	app.Name = "keytalk"
	app.Author = "keytalk.com"
	app.Usage = "usage here"
	app.Description = `description here`
	app.Flags = globalFlags
	app.CustomAppHelpTemplate = helpTemplate
	app.Before = func(c *cli.Context) error {
		return nil
	}

	app.Action = func(c *cli.Context) {
		var config client.Config
		if _, err := toml.DecodeFile(c.String("config"), &config); err != nil {
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
				output, err = os.OpenFile(os.ExpandEnv(log.Output), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
			}

			if err != nil {
				panic(err)
			}

			backend := logging.NewLogBackend(output, "", 0)
			backendLeveled := logging.AddModuleLevel(backend)

			level, err := logging.LogLevel(log.Level)
			if err != nil {
				panic(err)
			}

			backendLeveled.SetLevel(level, "")
			backendFormatter := logging.NewBackendFormatter(backendLeveled, format)

			logBackends = append(logBackends, backendFormatter)
		}

		logging.SetBackend(logBackends...)

		if client, err := client.New(&config); err != nil {
			panic(err)
		} else {
			client.ListenAndServe()
		}
	}

	// Run the app - exit on error.
	app.RunAndExitOnError()
}
