package main

import (
	"os"

	"github.com/KarlGW/secman"
)

func main() {
	os.Exit(secman.CLI(os.Args))
}
