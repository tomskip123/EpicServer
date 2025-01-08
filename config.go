package EpicServer

type Config struct {
	Server struct {
		Host        string
		Port        int
		Environment string
	}
	Security struct {
		SecureCookie bool
		CookieDomain string
		CSPHeader    string
		Origins      []string
	}
	SecretKey []byte
}

type Option func(*Config)

func SetHost(host string, port int) Option {
	return func(c *Config) {
		c.Server.Host = host
		c.Server.Port = port
	}
}

func SetSecretKey(secretKey []byte) Option {
	return func(c *Config) {
		c.SecretKey = secretKey
	}
}
