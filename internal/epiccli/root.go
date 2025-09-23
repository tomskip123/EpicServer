package epiccli

import (
	"flag"
	"fmt"
	"os"
)

func Run() int {
	if len(os.Args) < 2 {
		Usage()
		return 2
	}
	switch os.Args[1] {
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		force := fs.Bool("force", false, "overwrite existing files if present")
		_ = fs.Parse(os.Args[2:])
		target := "."
		if fs.NArg() >= 1 {
			target = fs.Arg(0)
		}
		if err := CmdInit(target, *force); err != nil {
			fmt.Fprintf(os.Stderr, "epic init error: %v\n", err)
			return 1
		}
		return 0
	case "validate":
		fs := flag.NewFlagSet("validate", flag.ExitOnError)
		_ = fs.Parse(os.Args[2:])
		configPath := "config.yaml"
		if fs.NArg() >= 1 {
			configPath = fs.Arg(0)
		}
		if err := CmdValidate(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
			return 1
		}
		fmt.Println("config is valid ✔")
		return 0
	case "controller", "g:controller", "g:c":
		fs := flag.NewFlagSet("controller", flag.ExitOnError)
		pathFlag := fs.String("path", ".", "target project directory (defaults to cwd)")
		force := fs.Bool("force", false, "overwrite existing files if present")
		_ = fs.Parse(os.Args[2:])
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "usage: epic controller <name> [--path dir] [--force]")
			return 2
		}
		name := fs.Arg(0)
		if err := CmdGenerateController(*pathFlag, name, *force); err != nil {
			fmt.Fprintf(os.Stderr, "epic controller error: %v\n", err)
			return 1
		}
		return 0
	case "help", "-h", "--help":
		Usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		Usage()
		return 2
	}
}

func Usage() {
	fmt.Println("epic - EpicServer project scaffolder")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  epic init [path] [--force]")
	fmt.Println("  epic controller <name> [--path dir] [--force]")
	fmt.Println("  epic validate [configPath]")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  epic init ./myapp")
	fmt.Println("  epic controller widgets --path ./myapp")
	fmt.Println("  epic validate ./myapp/config.yaml")
}
