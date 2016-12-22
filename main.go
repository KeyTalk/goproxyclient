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
	"github.com/fatih/color"
	"github.com/keytalk/client/bindata"
	"github.com/keytalk/client/client"
	"github.com/minio/cli"
	"github.com/mitchellh/go-homedir"
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
		Value: "~/Library/Keytalk/config.toml",
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

const LaunchAgent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.keytalk.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{ .Path }}</string>
        <string>-c</string>
        <string>{{ .Config }}</string>
        <string>run</string>
    </array>
    <key>KeepAlive</key>
    <false/>
    <key>EnvironmentVariables</key>
    <dict>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>{{ .BasePath }}</string>
    <key>StandardErrorPath</key>
    <string>{{ .LogPath }}</string>
    <key>StandardOutPath</key>
    <string>{{ .LogPath }}</string>
</dict>
</plist>`

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

	fmt.Println("[+] Keytalk client stopped cleanly.")
}

func bootstrap(c *cli.Context) {
	if keytalkPath, err := client.KeytalkPath(); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Could retrieve keytalk path: %s.", err.Error())))
		return
	} else {
		if f, err := os.Create(path.Join(keytalkPath, "config.toml")); err != nil {
			fmt.Println(color.RedString(fmt.Sprintf("[+] Could not create %s: %s.", keytalkPath, err.Error())))
			return
		} else {
			defer f.Close()

			if _, err := io.Copy(f, strings.NewReader(ConfigFile)); err != nil {
				fmt.Println(color.RedString(fmt.Sprintf("[+] Could not create configfile %s: %s.", keytalkPath, err.Error())))
				return
			}
		}

		cabundlePath := path.Join(keytalkPath, "ca-bundle.pem")
		if b, err := bindata.StaticCaBundlePemBytes(); err != nil {
		} else if err := ioutil.WriteFile(cabundlePath, b, 0644); err != nil {
		}

		capath := path.Join(keytalkPath, "ca.pem")
		if _, err := client.LoadCA(capath); err == nil {
		} else if _, err := client.GenerateNewCA(capath); err == nil {
		} else {
			fmt.Println(color.RedString(fmt.Sprintf("[+] Could not generate CA %s: %s.", keytalkPath, err.Error())))
			log.Error("Error generating CA: %s", err.Error())
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
	app.Author = "keytalk.com"
	app.Usage = "usage here"
	app.Description = `Keytalk client`
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
