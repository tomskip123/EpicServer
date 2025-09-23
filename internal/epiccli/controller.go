package epiccli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func CmdGenerateController(targetDir, rawName string, force bool) error {
	if rawName == "" {
		return fmt.Errorf("controller name is required")
	}
	abs, err := filepath.Abs(targetDir)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(filepath.Join(abs, "main.go")); err != nil || fi.IsDir() {
		return fmt.Errorf("%s does not look like an EpicServer app (missing main.go)", abs)
	}

	lc := strings.ToLower(sanitizeModuleName(rawName))
	if lc == "" {
		return fmt.Errorf("invalid controller name: %q", rawName)
	}
	typeName := toPascalCase(lc) + "Controller"

	if err := os.MkdirAll(filepath.Join(abs, "controllers"), 0o755); err != nil {
		return err
	}

	ctrlPath := filepath.Join(abs, "controllers", lc+".go")
	if err := writeControllerFile(ctrlPath, typeName, lc, force); err != nil {
		return err
	}

	moduleName, _ := readModuleName(filepath.Join(abs, "go.mod"))
	if moduleName == "" {
		moduleName = sanitizeModuleName(filepath.Base(abs))
	}
	if err := updateMainForController(filepath.Join(abs, "main.go"), moduleName, typeName, lc); err != nil {
		return err
	}

	fmt.Printf("Controller %q generated and registered.\n", lc)
	return nil
}

func writeControllerFile(path, typeName, routeName string, force bool) error {
	if exists(path) && !force {
		return nil
	}
	code := "package controllers\n\n" +
		"import (\n" +
		"\t\"net/http\"\n\n" +
		"\tepicserver \"github.com/tomskip123/EpicServer\"\n" +
		")\n\n" +
		"type " + typeName + " struct{}\n\n" +
		"func (c *" + typeName + ") Index(app *epicserver.EZApp) epicserver.Route {\n" +
		"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n" +
		"\t\t_ = epicserver.HTML(w, http.StatusOK, \"<h1>" + routeName + " index</h1>\")\n" +
		"\t})\n" +
		"}\n\n" +
		"func (c *" + typeName + ") Show(app *epicserver.EZApp) epicserver.Route   { return nil }\n" +
		"func (c *" + typeName + ") Edit(app *epicserver.EZApp) epicserver.Route   { return nil }\n" +
		"func (c *" + typeName + ") Post(app *epicserver.EZApp) epicserver.Route   { return nil }\n" +
		"func (c *" + typeName + ") Put(app *epicserver.EZApp) epicserver.Route    { return nil }\n" +
		"func (c *" + typeName + ") Delete(app *epicserver.EZApp) epicserver.Route { return nil }\n" +
		"func (c *" + typeName + ") Patch(app *epicserver.EZApp) epicserver.Route  { return nil }\n"
	return writeFile(path, []byte(code), 0o644)
}

func readModuleName(goModPath string) (string, error) {
	b, err := os.ReadFile(goModPath)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(b), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "module ")), nil
		}
	}
	return "", fmt.Errorf("module not found in go.mod")
}

func updateMainForController(mainPath, moduleName, typeName, routeName string) error {
	b, err := os.ReadFile(mainPath)
	if err != nil {
		return err
	}
	content := string(b)

	ctrlImport := fmt.Sprintf("\"%s/controllers\"", moduleName)
	updated, changed := addImportLine(content, ctrlImport)
	content = updated

	regLine := fmt.Sprintf("\tsrv.Controllers.Register(\"%s\", &controllers.%s{})\n", routeName, typeName)
	content, err = insertAfterNew(content, regLine)
	if err != nil {
		return err
	}

	if changed || content != string(b) {
		return os.WriteFile(mainPath, []byte(content), 0o644)
	}
	return nil
}

func addImportLine(content, newImport string) (string, bool) {
	if strings.Contains(content, newImport) {
		return content, false
	}
	idx := strings.Index(content, "import (")
	if idx >= 0 {
		end := strings.Index(content[idx:], ")")
		if end >= 0 {
			insertPos := idx + end
			before := content[:insertPos]
			after := content[insertPos:]
			indent := "\t"
			return before + "\n" + indent + newImport + after, true
		}
	}
	re := regexp.MustCompile(`(?m)^import\s+\"[^\"]+\"`)
	if loc := re.FindStringIndex(content); loc != nil {
		first := content[loc[0]:loc[1]]
		block := "import (\n\t" + first[len("import "):] + "\n\t" + newImport + "\n)"
		updated := content[:loc[0]] + block + content[loc[1]:]
		return updated, true
	}
	rePkg := regexp.MustCompile(`(?m)^package\s+\w+`)
	if loc := rePkg.FindStringIndex(content); loc != nil {
		insert := "\n\nimport (\n\t" + newImport + "\n)\n"
		updated := content[:loc[1]] + insert + content[loc[1]:]
		return updated, true
	}
	return content, false
}

func insertAfterNew(content, toInsert string) (string, error) {
	anchor := "epicserver.New("
	idx := strings.Index(content, anchor)
	if idx < 0 {
		callIdx := strings.Index(content, "srv.Start(")
		if callIdx < 0 {
			return content, fmt.Errorf("could not locate epicserver.New or srv.Start in main.go")
		}
		lineStart := strings.LastIndex(content[:callIdx], "\n")
		if lineStart < 0 {
			lineStart = 0
		}
		return content[:lineStart+1] + toInsert + content[lineStart+1:], nil
	}
	open := 0
	i := idx
	for ; i < len(content); i++ {
		switch content[i] {
		case '(':
			open++
		case ')':
			open--
			if open == 0 {
				j := i
				for j < len(content) && content[j] != '\n' {
					j++
				}
				return content[:j+1] + toInsert + content[j+1:], nil
			}
		}
	}
	return content, fmt.Errorf("could not balance parentheses after epicserver.New(")
}

var moduleSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_.\-/]`)

func sanitizeModuleName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, " ", "-")
	name = moduleSanitizeRe.ReplaceAllString(name, "-")
	if name == "" {
		return ""
	}
	for strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "-") {
		name = strings.TrimLeft(name, "./-")
	}
	return strings.ToLower(name)
}

func toPascalCase(s string) string {
	if s == "" {
		return s
	}
	seps := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	parts := seps.Split(s, -1)
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		if len(p) > 1 {
			b.WriteString(strings.ToLower(p[1:]))
		}
	}
	return b.String()
}
