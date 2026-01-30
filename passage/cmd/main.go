package main

import (
	"github.com/amrkmn/docker-credential-passage/credentials"
	"github.com/amrkmn/docker-credential-passage/passage"
)

// Version is set at build time via ldflags
var Version = "dev (unreleased)"

func main() {
	passage.SetVersion(Version)
	credentials.Serve(passage.Passage{})
}
