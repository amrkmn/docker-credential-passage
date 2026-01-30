package main

import (
	"github.com/amrkmn/docker-credential-passage/credentials"
	"github.com/amrkmn/docker-credential-passage/passage"
)

func main() {
	credentials.Serve(passage.Passage{})
}
