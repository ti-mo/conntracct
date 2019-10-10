// +build mage

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"

	"github.com/ti-mo/conntracct/pkg/kernel"
)

const (
	bpfBuildPath     = "build/bpf/"
	bpfAcctBuildPath = bpfBuildPath + "acct/"
	bpfAcctProbe     = "bpf/acct.c"
)

// Bpf is the namespace for all BPF-related build tasks.
type Bpf mg.Namespace

// Clean removes the BPF build directory and kernel configurations.
func (Bpf) Clean() error {

	fmt.Println("Removing directory", bpfBuildPath, "..")
	if err := os.RemoveAll(bpfBuildPath); err != nil {
		return err
	}

	for _, k := range kernel.Builds {
		p := path.Join(k.Directory(), ".config")
		fmt.Println("Removing", p, "..")
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}

	fmt.Println("So fresh, so clean.")
	return nil
}

// Build builds all BPF programs against all defined kernels.
func (Bpf) Build() error {

	// Basic check for build dependencies to avoid ugly errors.
	buildTools := []string{"clang", "llc", "statik"}
	for _, t := range buildTools {
		if _, err := exec.LookPath(t); err != nil {
			return fmt.Errorf("conntracct needs the following tools to build the eBPF probe: %s. %s",
				strings.Join(buildTools, ", "), err)
		}
	}

	// Create build target directory.
	if err := os.MkdirAll(bpfAcctBuildPath, os.ModePerm); err != nil {
		return err
	}

	// Build the acct probe against all Kernels defined in the kernel package.
	for _, k := range kernel.Builds {

		// Name of the resulting BPF object file.
		bpfObjectName := fmt.Sprintf("%s.o", k.Version)

		// Target path for the compiled BPF object.
		bpfObjectPath := path.Join(bpfAcctBuildPath, bpfObjectName)

		// Check if the acct probe source is newer than the probe's object in the build directory.
		run, err := target.Path(bpfObjectPath, bpfAcctProbe)
		if err != nil {
			return err
		}

		// Skip this build if the object is newer than the source.
		if !run {
			fmt.Println("Acct probe is up-to-date:", bpfObjectPath)
			continue
		}

		// Download and extract all kernels first.
		mg.Deps(Bpf.Kernels)

		if err := buildProbe(bpfAcctProbe, bpfObjectPath, k.Directory()); err != nil {
			fmt.Println("Failed to build probe against kernel", k.Version)
			return err
		}

		fmt.Println("Built acct probe", bpfObjectName)
	}

	// Bundle the BPF objects into the binary using statik.
	// Provide empty -c argument so statik doesn't write a package description.
	if err := sh.Run("statik", "-f", "-c", "", "-src", bpfBuildPath, "-dest", "pkg/", "-p", "bpf"); err != nil {
		return err
	}

	return nil
}

// Kernels downloads and extracts a list of kernels to a temporary directory.
func (Bpf) Kernels() error {

	var eg errgroup.Group

	for _, k := range kernel.Builds {

		// https://golang.org/doc/faq#closures_and_goroutines
		k := k

		eg.Go(func() error {
			// Get and unarchive the kernel.
			if err := k.Fetch(); err != nil {
				return err
			}

			// Configure the kernel with its specified parameters.
			if err := k.Configure(nil); err != nil {
				return err
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

// buildProbe builds a BPF program given its source file, destination object file
// and directory of the kernel source tree the program is to be built against.
func buildProbe(srcFile, destObj, kernelDir string) error {

	clangParams := []string{
		"-D__KERNEL__", "-D__BPF_TRACING__",
		"-fno-stack-protector",
		"-Wno-address-of-packed-member",
		"-Wno-gnu-variable-sized-type-not-at-end",
		"-Wno-unused-value",
		"-Wno-pointer-sign",
		"-Wno-compare-distinct-pointer-types",
		"-Wunused", "-Wall", "-Werror",
		"-O2", "-emit-llvm", "-ferror-limit=1",
		"-c", srcFile, // Input file
		"-o", "-", // Output to stdout
	}

	kdirs := []string{
		"-I%s/include",
		"-I%s/include/uapi",
		"-I%s/arch/x86/include",
		"-I%s/arch/x86/include/generated",
		// "-I%s/arch/x86/include/uapi",
		// "-I%s/include/generated/uapi",
	}

	// Resolve kernel directories in all include paths and append to clang params.
	for _, d := range kdirs {
		clangParams = append(clangParams, fmt.Sprintf(d, kernelDir))
	}

	llcParams := []string{
		"-march=bpf",
		"-filetype=obj",
		"-o", destObj,
	}

	clang := exec.Command("clang", clangParams...)
	llc := exec.Command("llc", llcParams...)

	// Redirect stderr of the builds to the terminal's stderr.
	clang.Stderr = os.Stderr
	llc.Stderr = os.Stderr

	llc.Stdin, _ = clang.StdoutPipe()
	llc.Stdout = os.Stdout

	if err := llc.Start(); err != nil {
		return err
	}

	// Run clang and wait for it to finish.
	if err := clang.Run(); err != nil {
		fmt.Println("Error running clang with args:", clang.Args)
		return err
	}

	if err := llc.Wait(); err != nil {
		fmt.Println("Error running llc with args:", llc.Args)
		return err
	}

	return nil
}
