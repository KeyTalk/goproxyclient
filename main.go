package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/KeyTalk/goproxyclient/bindata"
	"github.com/KeyTalk/goproxyclient/client"
	"github.com/fatih/color"
	"github.com/minio/cli"
	"github.com/mitchellh/go-homedir"
	"github.com/op/go-logging"
)

var version = "0.1"

var format = logging.MustStringFormatter(
	"%{time:2006-01-02 15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x} %{message}",
)

var log = logging.MustGetLogger("keytalk/client")

var globalFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "c,config",
		Usage: "config file",
		Value: "~/Library/KeyTalk/config.toml",
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
{{.Name} - {{.Usage}}

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

const ConfigFile = `
listen = "127.0.0.1:8080"

[[logging]]
output = "$HOME/Library/Logs/keytalk.log"
level = "info"

[[logging]]
output = "stdout"
level = "info"
`

func run(c *cli.Context) {
	// should we configure the proxy here?
	var config client.Config
	if _, err := toml.DecodeFile(configPath(c), &config); err != nil {
		panic(err)
	}

	logBackends := []logging.Backend{}
	for _, log := range config.Logging {
		var err error

		var output io.Writer = os.Stdout

		switch log.Output {
		case "stdout":
			output = os.Stdout
		case "stderr":
			output = os.Stderr
		default:
			output, err = os.OpenFile(os.ExpandEnv(log.Output), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
		}

		if err != nil {
			panic(err)
		}

		backend := logging.NewLogBackend(output, "", 0)
		backendFormatter := logging.NewBackendFormatter(backend, format)
		backendLeveled := logging.AddModuleLevel(backendFormatter)

		level, err := logging.LogLevel(log.Level)
		if err != nil {
			panic(err)
		}

		backendLeveled.SetLevel(level, "")

		logBackends = append(logBackends, backendFormatter)
	}

	logging.SetBackend(logBackends...)

	client, err := client.New(&config)
	if err != nil {
		panic(err)
	}

	// todo(nl5887): move trap signals to Main, this is not supposed to be in Serve
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, os.Kill, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case s := <-signalCh:
				if s == os.Interrupt {
					os.Exit(0)
				} else if s == syscall.SIGUSR1 {
				}
			}
		}
	}()

	client.ListenAndServe()
}

func bootstrap(c *cli.Context) {
	if keytalkPath, err := client.KeytalkPath(); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Could retrieve keytalk path: %s.", err.Error())))
		return
	} else if _, err := os.Stat(path.Join(keytalkPath, "config.toml")); !os.IsNotExist(err) {
	} else {
		if f, err := os.Create(path.Join(keytalkPath, "config.toml")); err != nil {
			log.Errorf("Could not create configfile %s: %s.", keytalkPath, err.Error())
			return
		} else {
			defer f.Close()

			if _, err := io.Copy(f, strings.NewReader(ConfigFile)); err != nil {
				log.Errorf("Could not create configfile %s: %s.", keytalkPath, err.Error())
				return
			}
		}

		cabundlePath := path.Join(keytalkPath, "ca-bundle.pem")
		if b, err := bindata.StaticCaBundlePemBytes(); err != nil {
			log.Errorf("Could not write ca-bundle: %s", err.Error())
		} else if err := ioutil.WriteFile(cabundlePath, b, 0644); err != nil {
			log.Errorf("Could not write ca-bundle: %s", err.Error())
		}

		capath := path.Join(keytalkPath, "ca.pem")
		if _, err := client.LoadCA(capath); err == nil {
		} else if _, err := client.GenerateNewCA(capath); err != nil {
			log.Errorf("Error generating CA: %s", err.Error())
		} else {
		}
	}
}

func configPath(c *cli.Context) string {
	home := ""
	if v, err := homedir.Dir(); err != nil {
		return ""
	} else {
		home = v
	}

	if v, err := filepath.Abs(strings.Replace(c.GlobalString("config"), "~", home, -1)); err == nil {
		return v
	} else {
		return c.GlobalString("config")
	}
}

func main() {
	// Set up app.
	app := cli.NewApp()
	app.Name = "keytalk"
	app.Author = "KeyTalk"
	app.Usage = ""
	app.Description = `KeyTalk client`
	app.Flags = globalFlags
	app.CustomAppHelpTemplate = helpTemplate
	app.Commands = []cli.Command{
		{
			Name:   "bootstrap",
			Action: bootstrap,
		},
		{
			Name:   "run",
			Action: run,
		},
	}

	app.Before = func(c *cli.Context) error {
		return nil
	}

	app.Action = func(c *cli.Context) {
	}

	// Run the app - exit on error.
	app.RunAndExitOnError()
}
