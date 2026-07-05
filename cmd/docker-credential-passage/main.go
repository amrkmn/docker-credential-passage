package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/amrkmn/docker-credential-passage/credentials"
	"github.com/amrkmn/docker-credential-passage/passage"
)

// Version is set at build time via ldflags.
// When empty, devVersion() derives v0.0.0-dev.$yyyy.MM.dd.$HHmmss.$sha from git.
var Version = ""

func main() {
	if Version == "" {
		Version = devVersion()
	}
	passage.SetVersion(Version)
	credentials.Serve(passage.Passage{})
}

func devVersion() string {
	now := time.Now()
	sha := ""
	if out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		sha = strings.TrimSpace(string(out))
	}
	if sha == "" {
		return fmt.Sprintf("v0.0.0-dev.%s", now.Format("2006.01.02.150405"))
	}
	return fmt.Sprintf("v0.0.0-dev.%s.%s", now.Format("2006.01.02.150405"), sha)
}
