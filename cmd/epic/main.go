package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	epicserver "github.com/tomskip123/EpicServer"
	"github.com/tomskip123/EpicServer/config"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		initCmd := flag.NewFlagSet("init", flag.ExitOnError)
		force := initCmd.Bool("force", false, "overwrite existing files if present")
		_ = initCmd.Parse(os.Args[2:])
		target := "."
		if initCmd.NArg() >= 1 {
			target = initCmd.Arg(0)
		}
		if err := cmdInit(target, *force); err != nil {
			fmt.Fprintf(os.Stderr, "epic init error: %v\n", err)
			os.Exit(1)
		}
	case "validate":
		valCmd := flag.NewFlagSet("validate", flag.ExitOnError)
		_ = valCmd.Parse(os.Args[2:])
		configPath := "config.yaml"
		if valCmd.NArg() >= 1 {
			configPath = valCmd.Arg(0)
		}
		if err := cmdValidate(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("config is valid ✔")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("epic - EpicServer project scaffolder")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  epic init [path] [--force]")
	fmt.Println("  epic validate [configPath]")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  epic init ./myapp")
	fmt.Println("  epic validate ./myapp/config.yaml")
}

func cmdValidate(path string) error {
	_, err := config.Load(path)
	return err
}

func cmdInit(target string, force bool) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}

	// Directories
	dirs := []string{
		"controllers",
		"middleware",
		filepath.Join("templates"),
		filepath.Join("templates", "components"),
		filepath.Join("templates", "layouts"),
		filepath.Join("templates", "lazy"),
		filepath.Join("templates", "pages"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(abs, d), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	// Files
	if err := writeConfigYAML(filepath.Join(abs, "config.yaml"), force); err != nil {
		return err
	}
	if err := writeENV(filepath.Join(abs, ".env"), force); err != nil {
		return err
	}
	if err := writeMainGo(filepath.Join(abs, "main.go"), force); err != nil {
		return err
	}
	if err := writeGoMod(filepath.Join(abs, "go.mod"), abs, force); err != nil {
		return err
	}
	if err := writeEmpty(filepath.Join(abs, "go.sum"), force); err != nil {
		return err
	}

	// Template starter files
	if err := writeBaseLayout(filepath.Join(abs, "templates", "layouts", "base.html"), force); err != nil {
		return err
	}
	if err := writeHomePage(filepath.Join(abs, "templates", "pages", "home.html"), force); err != nil {
		return err
	}
	if err := writeNavComponent(filepath.Join(abs, "templates", "components", "nav.html"), force); err != nil {
		return err
	}
	if err := writeLazySample(filepath.Join(abs, "templates", "lazy", "hello.html"), force); err != nil {
		return err
	}

	// Placeholders to keep dirs in VCS
	_ = writeEmpty(filepath.Join(abs, "controllers", ".keep"), false)
	_ = writeEmpty(filepath.Join(abs, "middleware", ".keep"), false)

	fmt.Printf("Scaffold created at %s\n", abs)
	return nil
}

func writeConfigYAML(path string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	cfg := config.Default()
	b, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	header := "# EpicServer configuration\n"
	return writeFile(path, append([]byte(header), b...), 0o644)
}

func writeENV(path string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	content := strings.Join([]string{
		"# Example environment overrides (optional)",
		"# APP_NAME=epicserver",
		"# APP_ENV=dev",
		"# SERVER_HOST=0.0.0.0",
		"# SERVER_PORT=8080",
		"# LOGGER_IS_DEBUG=false",
		"# LOGGER_REQUEST_LOG_FORMAT=off",
		"# DB_DRIVER=sqlite",
		"# DB_DSN=file:epic.db?_busy_timeout=5000",
		"# DB_MAX_OPEN_CONNS=10",
		"# DB_MAX_IDLE_CONNS=5",
		"# DB_CONN_MAX_LIFETIME=30m",
		"",
	}, "\n")
	return writeFile(path, []byte(content), 0o644)
}

func writeMainGo(path string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	code := `package main

import (
    "log"
    "net/http"

    epicserver "github.com/tomskip123/EpicServer"
)

func main() {
    srv := epicserver.New("config.yaml",
        epicserver.WithBaseDir("templates"),
        epicserver.WithDev(true),
    )

    // Mount a sample home page rendered from templates/pages/home.html
    srv.App.Render.MountGet("/", "home", func(r *http.Request) any {
        return epicserver.H{"Title": "Welcome to EpicServer"}
    })

    if err := srv.Start(srv.App); err != nil {
        log.Fatal(err)
    }
}
`
	return writeFile(path, []byte(code), 0o644)
}

func writeGoMod(path, absTarget string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	moduleName := sanitizeModuleName(filepath.Base(absTarget))
	if moduleName == "" {
		moduleName = "epicapp"
	}
	content := fmt.Sprintf("module %s\n\nGo 1.24.5\n", moduleName)
	// Normalize the leading token to lowercase "go" if accidentally capitalized
	content = strings.Replace(content, "Go ", "go ", 1)
	return writeFile(path, []byte(content), 0o644)
}

func writeBaseLayout(path string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	tpl := `{{define "base"}}
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{{with .Title}}{{.}}{{else}}EpicServer{{end}}</title>
    {{block "head" .}}{{end}}
  </head>
  <body>
    {{template "components/nav" .}}
    <main>
      {{block "content" .}}{{end}}
    </main>
    {{block "scripts" .}}{{end}}
  </body>
  </html>
{{end}}
`
	return writeFile(path, []byte(tpl), 0o644)
}

func writeHomePage(path string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	tpl := `{{define "content"}}
<h1>{{with .Title}}{{.}}{{else}}Hello, EpicServer!{{end}}</h1>
<p>If you see this, your scaffold worked.</p>
{{end}}
`
	return writeFile(path, []byte(tpl), 0o644)
}

func writeNavComponent(path string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	tpl := `{{define "components/nav"}}
<nav style="padding: 8px 0; border-bottom: 1px solid #ddd; margin-bottom: 16px;">
  <a href="/">Home</a>
  <!-- add more links here -->
  </nav>
{{end}}
`
	return writeFile(path, []byte(tpl), 0o644)
}

func writeLazySample(path string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	tpl := `{{define "hello.html"}}
<div>Hello from lazy template!</div>
{{end}}
`
	return writeFile(path, []byte(tpl), 0o644)
}

func writeEmpty(path string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	return writeFile(path, []byte(""), 0o644)
}

func writeFile(path string, data []byte, perm fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

var moduleSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_.\-/]`)

func sanitizeModuleName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, " ", "-")
	name = moduleSanitizeRe.ReplaceAllString(name, "-")
	if name == "" {
		return ""
	}
	// avoid leading dot or slash
	for strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "-") {
		name = strings.TrimLeft(name, "./-")
	}
	return strings.ToLower(name)
}

// Ensure references are kept for import validation when building the CLI alone.
var _ = errors.New
var _ = epicserver.Renderer{}
