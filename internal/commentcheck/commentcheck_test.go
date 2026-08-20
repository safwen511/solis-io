// Package commentcheck enforces the repository's function-documentation boundary.
package commentcheck

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var (
	shellFunctionPattern  = regexp.MustCompile(`^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{`)
	pythonFunctionPattern = regexp.MustCompile(`^([ \t]*)(?:async[ \t]+)?def[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b`)
	jqFunctionPattern     = regexp.MustCompile(`^[ \t]*def[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b`)
	cFunctionPattern      = regexp.MustCompile(`^[ \t]*(?:static[ \t]+)?(?:__always_inline[ \t]+)?(?:int|void|__u[0-9]+|struct[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\*)[ \t]+([A-Za-z_][A-Za-z0-9_]*)\(`)
	bpfProgramPattern     = regexp.MustCompile(`BPF_PROG\(([A-Za-z_][A-Za-z0-9_]*)`)
)

// TestNamedGoFunctionsHaveComments prevents undocumented production and test functions.
func TestNamedGoFunctionsHaveComments(t *testing.T) {
	root := repositoryRoot(t)
	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}
			set := token.NewFileSet()
			file, err := parser.ParseFile(set, path, nil, parser.ParseComments)
			if err != nil {
				t.Errorf("parse %s: %v", path, err)
				return nil
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if function.Doc == nil || strings.TrimSpace(function.Doc.Text()) == "" {
					t.Errorf("%s:%d: function %s has no explanatory comment", path, set.Position(function.Pos()).Line, function.Name.Name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", directory, err)
		}
	}
}

// TestScriptFunctionsHaveComments keeps shell, Python, and jq helper contracts visible.
func TestScriptFunctionsHaveComments(t *testing.T) {
	root := repositoryRoot(t)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "dist" || entry.Name() == "vendor" ||
				(entry.Name() == "reports" && filepath.Base(filepath.Dir(path)) == "lab") {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".sh":
			checkLineComments(t, path, shellFunctionPattern, "#")
		case ".jq":
			checkLineComments(t, path, jqFunctionPattern, "#")
		case ".py":
			checkPythonDocstrings(t, path)
		case ".c":
			checkCFunctionComments(t, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// checkCFunctionComments accepts a direct block comment or one separated only by a SEC annotation.
func checkCFunctionComments(t *testing.T, path string) {
	t.Helper()
	lines := readLines(t, path)
	for index, line := range lines {
		match := cFunctionPattern.FindStringSubmatch(line)
		if program := bpfProgramPattern.FindStringSubmatch(line); program != nil {
			match = program
		}
		if match == nil {
			continue
		}
		cursor := index - 1
		for cursor >= 0 && strings.TrimSpace(lines[cursor]) == "" {
			cursor--
		}
		if cursor >= 0 && strings.HasPrefix(strings.TrimSpace(lines[cursor]), "SEC(") {
			cursor--
			for cursor >= 0 && strings.TrimSpace(lines[cursor]) == "" {
				cursor--
			}
		}
		if cursor < 0 || (!strings.HasSuffix(strings.TrimSpace(lines[cursor]), "*/") &&
			!strings.HasPrefix(strings.TrimSpace(lines[cursor]), "//")) {
			t.Errorf("%s:%d: C function %s has no adjacent explanatory comment", path, index+1, match[1])
		}
	}
}

// repositoryRoot resolves the checkout from this test file without depending on the process cwd.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve comment-check source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// checkLineComments requires a directly adjacent comment for each matched script helper.
func checkLineComments(t *testing.T, path string, pattern *regexp.Regexp, marker string) {
	t.Helper()
	lines := readLines(t, path)
	for index, line := range lines {
		match := pattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if index == 0 || !strings.HasPrefix(strings.TrimSpace(lines[index-1]), marker) {
			t.Errorf("%s:%d: function %s has no adjacent explanatory comment", path, index+1, match[len(match)-1])
		}
	}
}

// checkPythonDocstrings requires the first function statement to be a docstring.
func checkPythonDocstrings(t *testing.T, path string) {
	t.Helper()
	lines := readLines(t, path)
	for index := 0; index < len(lines); index++ {
		match := pythonFunctionPattern.FindStringSubmatch(lines[index])
		if match == nil {
			continue
		}
		declarationEnd := index
		for declarationEnd < len(lines) && !pythonDeclarationEnds(lines[declarationEnd]) {
			declarationEnd++
		}
		body := declarationEnd + 1
		for body < len(lines) && strings.TrimSpace(lines[body]) == "" {
			body++
		}
		if body >= len(lines) || !strings.HasPrefix(strings.TrimSpace(lines[body]), `"""`) {
			t.Errorf("%s:%d: function %s has no leading docstring", path, index+1, match[2])
		}
	}
}

// pythonDeclarationEnds recognizes a signature terminator before an optional inline comment.
func pythonDeclarationEnds(line string) bool {
	code := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
	return strings.HasSuffix(code, ":")
}

// readLines reads a text source once and preserves stable line numbers for failures.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}
