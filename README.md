# Go-NSJail: Go Bindings for NSJail

[![Go Reference](https://pkg.go.dev/badge/github.com/your-username/go-nsjail.svg)](https://pkg.go.dev/github.com/your-username/go-nsjail)

This package provides a complete Go wrapper for the [NSJail](https://github.com/google/nsjail) process isolation tool. It allows you to configure and launch sandboxed processes programmatically from Go using a fluent, idiomatic builder API.

## Features

-   **Fluent Builder API**: Chain methods to configure the jail in a readable way.
-   **Complete Coverage**: Supports all command-line flags from the NSJail tool.
-   **Type-Safe Constants**: Uses constants for modes and other enumerations to prevent typos.
-   **Flexible Execution**: Returns a standard `*exec.Cmd`, giving you full control over `stdin`, `stdout`, `stderr`, and process execution (`Run`, `Start`, `Output`, etc.).
-   **Well-Documented**: The API is thoroughly documented with descriptions taken directly from NSJail's help output.

## Prerequisites

The `nsjail` binary must be installed on the system and ideally available in the system's `PATH`. If it's installed elsewhere, you can specify its location using the `WithPath()` method.

```bash
# Example installation on Debian/Ubuntu
sudo apt-get update
sudo apt-get install nsjail
```

## Installation

```sh
go get github.com/your-username/go-nsjail
```

## Quick Start

Here's how to run `/bin/bash` in a minimal, isolated environment, similar to the examples in the official NSJail documentation.

```go
package main

import (
	"log"
	"os"
	"os/exec"

	"github.com/your-username/go-nsjail"
)

func main() {
	// Configure the jail using the fluent builder API.
	// This will construct the command:
	// nsjail -Mo --user 0 --group 99999 -R /bin/ -R /lib -R /lib64/ -T /dev -R /dev/urandom --keep_caps -- /bin/bash -i
	cmd, err := nsjail.New("/bin/bash", "-i").
		WithMode(nsjail.ModeOnce).
		WithUser("0").
		WithGroup("99999").
		AddBindMountRO("/bin/").
		AddBindMountRO("/lib/").
		AddBindMountRO("/lib64/").
		AddTmpfsMount("/dev").
		AddBindMountRO("/dev/urandom").
		KeepCaps().
		Exec()

	if err != nil {
		log.Fatalf("Failed to create nsjail command: %v", err)
	}

	// For an interactive shell, connect stdin, stdout, and stderr.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Println("Starting interactive bash shell in nsjail...")
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("Jailed process exited with code %d", exitErr.ExitCode())
		} else {
			log.Fatalf("Failed to run nsjail: %v", err)
		}
	}
	log.Println("Jailed process finished.")
}
```

## Examples

The `examples/` directory contains Go implementations of the use-cases described in the official NSJail README.

-   [Minimal Bash Shell](./examples/minimal_bash/main.go)
-   [Constrained `find` command](./examples/constrained_find/main.go)
-   [Network Service (inetd style)](./examples/network_service/main.go)
-   [Seccomp-constrained Shell](./examples/seccomp_shell/main.go)

## API

For a complete list of all available options, see the [GoDoc reference](https://pkg.go.dev/github.com/your-username/go-nsjail). The method names directly correspond to the `nsjail` command-line flags.