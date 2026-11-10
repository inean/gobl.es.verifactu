//go:build mage

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"
)

const (
	name       = "gobl.es.verifactu"
	mainBranch = "main"
)

// Build the binary
func Build() error {
	output, err := executable()
	if err != nil {
		return err
	}
	changed, err := target.Dir(output, ".")
	if os.IsNotExist(err) || (err == nil && changed) {
		return build(output)
	}
	return nil
}

// Install the binary into your go bin path
func Install() error {
	bin, err := trimOutput("go", "env", "GOBIN")
	if err != nil {
		return err
	}
	if bin == "" {
		gopath, err := trimOutput("go", "env", "GOPATH")
		if err != nil {
			return err
		}
		paths := filepath.SplitList(gopath)
		if len(paths) == 0 {
			return fmt.Errorf("GOBIN and GOPATH are empty")
		}
		bin = filepath.Join(paths[0], "bin")
	}
	output, err := executable()
	if err != nil {
		return err
	}
	return build(filepath.Join(bin, output))
}

func executable() (string, error) {
	ext, err := trimOutput("go", "env", "GOEXE")
	return name + ext, err
}

func build(output string) error {
	args := []string{"build", "-o", output}
	flags, err := buildFlags()
	if err != nil {
		return err
	}
	args = append(args, flags...)
	args = append(args, "./cmd/gobl.verifactu")
	return sh.RunV("go", args...)
}

func buildFlags() ([]string, error) {
	ldflags := []string{
		fmt.Sprintf("-X 'main.date=%s'", date()),
	}
	if v, err := version(); err != nil {
		return nil, err
	} else if v != "" {
		ldflags = append(ldflags, fmt.Sprintf("-X 'main.version=%s'", v))
	}

	out := []string{}
	if len(ldflags) > 0 {
		out = append(out, "-ldflags="+strings.Join(ldflags, " "))
	}
	return out, nil
}

func version() (string, error) {
	vt, err := versionTag()
	if err != nil {
		return "", err
	}
	v := []string{vt}
	if b, err := branch(); err != nil {
		return "", err
	} else if b != mainBranch {
		v = append(v, b)
	}
	if uncommittedChanges() {
		v = append(v, "uncommitted")
	}
	return strings.Join(v, "-"), nil
}

func versionTag() (string, error) {
	return trimOutput("git", "describe", "--tags") // no "--exact-match"
}

func branch() (string, error) {
	return trimOutput("git", "rev-parse", "--abbrev-ref", "HEAD")
}

func uncommittedChanges() bool {
	err := sh.Run("git", "diff-index", "--quiet", "HEAD", "--")
	return err != nil
}

func date() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func trimOutput(cmd string, args ...string) (string, error) {
	txt, err := sh.Output(cmd, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(txt), nil
}
