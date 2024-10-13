package structs

type ServerConfig struct {
	Host                 string
	SecureCookie         bool
	CookieDomain         string
	TemplatesDir         string
	PackageTemplatesDir  string
	Origins              []string
	ViteManifestFilePath string
	CSPHeader            string
	NotificationHost     string
	RouteSkipAuth        []string
}

type DbConfigCollection = map[string]CollectionInterface
type DbConfig struct {
	DbUri       string
	DbName      string
	Collections DbConfigCollection
}
