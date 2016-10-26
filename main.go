package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/fatih/color"
	"github.com/keytalk/client/client"
	"github.com/keytalk/rccd"
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

const LaunchAgent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.keytalk.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/remco/Projects/keytalk/keytalk-client/src/github.com/keytalk/client/bin/keytalk</string>
        <string>-c</string>
        <string>/Users/remco/Projects/keytalk/keytalk-client/src/github.com/keytalk/client/config.toml</string>
    </array>
    <key>KeepAlive</key>
    <false/>
    <key>EnvironmentVariables</key>
    <dict>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/Users/remco/Projects/keytalk/keytalk-client/src/github.com/keytalk/client/</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/keytalk.log</string>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/keytalk.log</string>
</dict>
</plist>`

func Start(c *cli.Context) {
	cmd := exec.Command("launchctl", "start", "com.keytalk.client")
	if err := cmd.Run(); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Could start agent: %s.", err.Error())))
		return
	}
}

func Stop(c *cli.Context) {
	cmd := exec.Command("launchctl", "stop", "com.keytalk.client")
	if err := cmd.Run(); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Could stop agent: %s.", err.Error())))
		return
	}
}

func Install(c *cli.Context) {
	if home, err := homedir.Dir(); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Could retrieve homedir: %s.", err.Error())))
		return
	} else {
		destPath := path.Join(home, "Library", "LaunchAgents", "com.keytalk.plist")

		if err := ioutil.WriteFile(destPath, []byte(LaunchAgent), 600); err != nil {
			fmt.Println(color.RedString(fmt.Sprintf("[+] Could write plist file %s: %s.", destPath, err.Error())))
			return
		}

		cmd := exec.Command("launchctl", "unload", destPath)
		if err := cmd.Run(); err != nil {
			fmt.Println(color.RedString(fmt.Sprintf("[+] Could unload agent %s: %s.", destPath, err.Error())))
		}

		cmd = exec.Command("launchctl", "load", destPath)
		if err := cmd.Run(); err != nil {
			fmt.Println(color.RedString(fmt.Sprintf("[+] Could load agent %s: %s.", destPath, err.Error())))
			return
		}
	}
}

func Load(c *cli.Context) {
	if len(c.Args()) != 1 {
		fmt.Println("Usage: keytalk load {rccd file}")
		return
	}

	sourcePath := c.Args()[0]

	if _, err := rccd.Open(sourcePath); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Invalid rccd file %s: %s.", sourcePath, err.Error())))
		return
	}

	f, err := os.Open(sourcePath)
	if err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Could not open file %s: %s.", sourcePath, err.Error())))
		return
	}

	defer f.Close()

	if home, err := homedir.Dir(); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Could retrieve homedir: %s.", err.Error())))
		return
	} else {
		destPath := path.Join(home, ".keytalk", path.Base(c.Args()[0]))
		if f2, err := os.Create(destPath); err != nil {
			fmt.Println(color.RedString(fmt.Sprintf("[+] Could not create %s: %s.", destPath, err.Error())))
			return
		} else {
			defer f2.Close()

			if _, err := io.Copy(f2, f); err != nil {
				fmt.Println(color.RedString(fmt.Sprintf("[+] Could not copy %s to %s: %s.", sourcePath, destPath, err.Error())))
				return
			} else {
				fmt.Println(color.YellowString(fmt.Sprintf("[+] RCCD %s successfully installed.", sourcePath)))
			}
		}
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
			Name:   "install",
			Action: Install,
		},
		{
			Name:   "start",
			Action: Start,
		},
		{
			Name:   "stop",
			Action: Stop,
		},
		{
			Name:   "load",
			Action: Load,
		},
	}

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

		// todo(nl5887): move trap signals to Main, this is not supposed to be in Serve
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, os.Interrupt, os.Kill, syscall.SIGUSR1)

		go func() {
			for {
				select {
				case s := <-signalCh:
					fmt.Println(s)
					if s == os.Interrupt {
					} else if s == syscall.SIGUSR1 {
					}
				}
			}
		}()

		if client, err := client.New(&config); err != nil {
			panic(err)
		} else {
			client.ListenAndServe()
		}

		fmt.Println("[+] Keytalk client stopped cleanly.")
	}

	// Run the app - exit on error.
	app.RunAndExitOnError()
}
