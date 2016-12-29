package client

type Config struct {
	ListenerString string `toml:"listen"`

	Username string `toml:"username"`
	Password string `toml:"password"`
	Service  string `toml:"service"`

	Logging []struct {
		Output string `toml:"output"`
		Level  string `toml:"level"`
	} `toml:"logging"`
}
