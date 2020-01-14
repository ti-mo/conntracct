// +build mage

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"
)

const (
	app       = "conntracct"
	buildPath = "build/conntracct"
)

var (
	build      = sh.RunCmd("go", "build", "-o", buildPath)
	goreleaser = sh.RunCmd("goreleaser", "release", "--rm-dist")
)

// Build builds the application.
func Build() error {

	// Watch for files newer than the app in these directories.
	mod, err := target.Dir(buildPath, "bpf", "pkg", "cmd", "internal")
	if err != nil {
		return err
	}

	if mod {

		realPath := realPath(buildPath)

		// Unlink the existing binary so it can be replaced without stopping the daemon first.
		if err := sh.Rm(realPath); err != nil {
			return err
		}

		// Build the application.
		if err := build(); err != nil {
			return err
		}

		// 'Minimal' capability set to run without being uid 0.
		// cap_sys_admin for calling bpf().
		// cap_ipc_lock for locking memory for the ring buffer.
		// cap_dac_override for opening /sys/kernel/debug/tracing/*
		// cap_net_admin for managing sysctl net.netfilter.nf_conntrack_acct
		if err := sh.Run("sudo", "setcap", "cap_sys_admin,cap_ipc_lock,cap_net_admin,cap_dac_override,cap_sys_resource+eip", realPath); err != nil {
			return err
		}

		fmt.Printf("Successfully built %s!\n", buildPath)
		return nil
	}

	fmt.Println(buildPath, "already up to date.")
	return nil
}

// Dev brings up a docker-compose stack and runs the application with modd for live reloading.
func Dev() error {

	if err := sh.Run("docker-compose", "-f", "test/docker-compose.yml", "-p", app, "up", "-d"); err != nil {
		return err
	}

	fmt.Println("Starting live-reload with modd..")
	if err := sh.RunV("modd"); err != nil {
		return err
	}

	return nil
}

// Generate runs `go generate` on all packages.
func Generate() error {
	if err := sh.RunV("go", "generate", "-x", "./..."); err != nil {
		return err
	}

	fmt.Println("Successfully ran go generate.")
	return nil
}

// Lint runs golangci-lint with the project's configuration.
func Lint() error {
	return sh.RunV("golangci-lint", "run")
}

// Release builds and publishes the release to GitHub.
func Release() error {
	return goreleaser()
}

// Snapshot creates a local snapshot release without publishing to GitHub.
func Snapshot() error {
	v, err := sh.Output("go", "version")
	if err != nil {
		return err
	}

	os.Setenv("GOVERSION", v)
	return goreleaser("--snapshot")
}

// realPath resolves (nested) symlinks. If the target of a nested symlink does
// not exist, falls back to the target of the first symlink.
func realPath(path string) string {

	fi, err := os.Lstat(path)
	if err != nil {
		// Return the input string if the path doesn't exist (yet), there's nothing to resolve.
		return path
	}

	if (fi.Mode() & os.ModeSymlink) != 0 {
		// Try to recursive symlinks.
		realPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			// Return the symlink target path if target file doesn't exist.
			ret, _ := os.Readlink(path)
			return ret
		}

		return realPath
	}

	return path
}
