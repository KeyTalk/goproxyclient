package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
	"github.com/kardianos/osext"
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
		Value: "~/.keytalk/config.toml",
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
        <string>{{ .Path }}</string>
        <string>-c</string>
        <string>{{ .Config }}</string>
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
    <string>/usr/local/var/log/keytalk.log</string>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/keytalk.log</string>
</dict>
</plist>`

const ConfigFile = `
listen = "127.0.0.1:8080"

[[logging]]
output = "$HOME/.keytalk/log.txt"
level = "debug"

[[logging]]
output = "stdout"
level = "debug"
`

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

func GetActiveNetworkService() string {
	cmd := exec.Command("/usr/sbin/networksetup", "-listnetworkserviceorder")
	if output, err := cmd.Output(); err != nil {
		log.Info("Could not retrieve output", err.Error())
	} else {
		re := regexp.MustCompile(`\(Hardware Port: ([^,]+), Device: ([a-z0-9]+)\)`)
		matches := re.FindAllStringSubmatch(string(output), -1)

		for _, match := range matches {
			cmd := exec.Command("/sbin/ifconfig", match[2])
			if output, err := cmd.Output(); err != nil {
				// log.Errorf("Could not read output of ifconfig (%s): %s", match[2], err.Error())
			} else if matched, err := regexp.MatchString("status: active", string(output)); err != nil {
				log.Errorf("Could not match output (%s): %s", match[2], err.Error())
			} else if matched {
				return (strings.TrimSpace(match[1]))
			}
		}
	}

	return ""
}

func Install(c *cli.Context) {
	network := GetActiveNetworkService()

	cmd := exec.Command("/usr/sbin/networksetup", "-setsecurewebproxy", network, "127.0.0.1", "8080")
	if err := cmd.Run(); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Error configuring proxy for network service %s: %s.", network, err.Error())))
	} else {
		fmt.Println(color.YellowString(fmt.Sprintf("[+] Proxy configured for network service %s.", network)))
	}

	if home, err := homedir.Dir(); err != nil {
		fmt.Println(color.RedString(fmt.Sprintf("[+] Could retrieve homedir: %s.", err.Error())))
		return
	} else {
		destPath := path.Join(home, ".keytalk")

		if f, err := os.Create(path.Join(destPath, "config.toml")); err != nil {
			fmt.Println(color.RedString(fmt.Sprintf("[+] Could not create %s: %s.", destPath, err.Error())))
			return
		} else {
			defer f.Close()

			if _, err := io.Copy(f, strings.NewReader(ConfigFile)); err != nil {
				fmt.Println(color.RedString(fmt.Sprintf("[+] Could not create configfile %s: %s.", destPath, err.Error())))
				return
			}
		}

		destPath = path.Join(home, "Library", "LaunchAgents", "com.keytalk.plist")

		t := template.New("")

		if t, err = t.Parse(LaunchAgent); err != nil {
			fmt.Println(color.RedString(fmt.Sprintf("[+] Could not parse agent template: %s.", err.Error())))
			return
		}

		executablePath := ""
		if v, err := osext.Executable(); err == nil {
			executablePath = v
		}

		buf := &bytes.Buffer{}
		if err = t.Execute(buf, map[string]string{
			"Path":     executablePath,
			"BasePath": path.Dir(executablePath),
			"Config":   configPath(c),
		}); err != nil {
			return
		}

		if err := ioutil.WriteFile(destPath, buf.Bytes(), 0600); err != nil {
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

		fmt.Println(color.YellowString(fmt.Sprintf("[+] Keytalk Client agent successfully installed.")))
	}
}

func loadRCCD(p string) {
	if r, err := rccd.Open(p); err != nil {
		log.Error("Could not load rccd file: %s", err.Error())
	} else if home, err := homedir.Dir(); err != nil {
	} else {
		loginKeychain := path.Join(home, "Library", "Keychains", "login.keychain")

		for _, c := range []*x509.Certificate{r.PCA, r.UCA} {
			tmpfile, err := ioutil.TempFile("", "keytalk")
			if err != nil {
				return
			}

			defer os.Remove(tmpfile.Name())

			cert2 := &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}
			if err := pem.Encode(tmpfile, cert2); err != nil {
				fmt.Println(color.RedString(fmt.Sprintf("[+] Could not write %s: %s.", tmpfile, err.Error())))
			}

			cmd := exec.Command("/usr/bin/security", "add-trusted-cert", "-r", "trustRoot", "-k", loginKeychain, tmpfile.Name())
			if err := cmd.Run(); err != nil {
				fmt.Println(color.RedString(fmt.Sprintf("[+] Could install ca certificate: %s.", err.Error())))
			} else {
				fmt.Println(color.YellowString(fmt.Sprintf("[+] Installed ca certificate.")))
			}
		}
	}
}

func configDir(c *cli.Context) (string, error) {
	home := ""
	if v, err := homedir.Dir(); err != nil {
		return "", err
	} else {
		home = v
	}

	return path.Join(home, ".keytalk"), nil
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

func runWatcher(c *cli.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if path.Ext(event.Name) != ".rccd" {
					continue
				}

				if event.Op != fsnotify.Write {
					continue
				}

				loadRCCD(event.Name)
			case err := <-watcher.Errors:
				log.Error("error:", err)
			}
		}
	}()

	dir, err := configDir(c)
	if err != nil {

	}

	err = watcher.Add(dir)
	if err != nil {
		log.Fatal(err)
	}
	<-done
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
	}

	app.Before = func(c *cli.Context) error {
		return nil
	}

	app.Action = func(c *cli.Context) {
		home := ""
		if v, err := configDir(c); err != nil {
			fmt.Println(color.RedString(fmt.Sprintf("[+] Could retrieve config directory: %s.", err.Error())))
			return
		} else {
			home = v
		}

		if _, err := os.Stat(path.Join(home, ".keytalk", "config.toml")); err == nil {
		} else if os.IsNotExist(err) {
			// config doesn't exist, install
			Install(c)
		}

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

		go runWatcher(c)

		log.Infof("BLA %s", c.Args()[0:])

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
