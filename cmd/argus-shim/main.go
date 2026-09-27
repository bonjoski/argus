package main

import (
	"os"
	"path/filepath"

	"bonjoski/argus/internal/cli"
)

func main() {
	progName := filepath.Base(os.Args[0])

	if progName == "argus-shim" {
		if len(os.Args) < 2 {
			os.Exit(1)
		}
		// argus-shim <tool> <args...>
		os.Args = append([]string{"argus", "shim", "exec"}, os.Args[1:]...)
	} else {
		// Invoked directly via symlink (e.g. ~/.argus/bin/npm)
		os.Args = append([]string{"argus", "shim", "exec", progName}, os.Args[1:]...)
	}

	cli.Execute()
}
