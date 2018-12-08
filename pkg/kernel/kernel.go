package kernel

import (
	"fmt"
	"os"
	"path"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/ti-mo/kconfig"
)

// Params is a map of kernel parameters.
type Params map[string]string

// Kernel represents a kernel object.
type Kernel struct {
	Version string
	URL     string
	Params  Params
}

// ArchiveName returns the file name of the archive based on its URL.
func (k Kernel) ArchiveName() string {
	return path.Base(k.URL)
}

// ArchivePath returns the path of the archive on disk.
func (k Kernel) ArchivePath() string {
	return path.Join(buildDir, k.ArchiveName())
}

// Name returns the name (plain version) of the kernel based on the name of the archive.
func (k Kernel) Name() string {
	return trimExt(k.ArchiveName())
}

// Directory returns the path on disk where the kernel is extracted.
func (k Kernel) Directory() string {
	return path.Join(buildDir, k.Name())
}

// Fetch ensures that a given kernel is downloaded and extracted to the temp directory.
func (k Kernel) Fetch() error {

	if mg.Verbose() {
		fmt.Println("Fetching ", k.Name(), "..")
	}

	if err := os.MkdirAll(buildDir, os.ModePerm); err != nil {
		return err
	}

	if err := curl(k.URL, k.ArchivePath()); err != nil {
		return err
	}

	if err := unarchive(k.ArchivePath(), buildDir, k.Directory()); err != nil {
		return err
	}

	if mg.Verbose() {
		fmt.Println("Successfully fetched", k.Name())
	}

	return nil
}

// Configure configures and prepares the kernel with the requested settings.
// If params is nil, the parameters defined on the Kernel will be used.
func (k Kernel) Configure(params Params) error {

	if mg.Verbose() {
		fmt.Println("Configuring", k.Name(), "..")
	}

	kcfile := path.Join(k.Directory(), ".config")

	// Initialize the default configuration to '.config'.
	if err := sh.Run("make", "-C", k.Directory(), "defconfig"); err != nil {
		return err
	}

	kc := kconfig.New()
	if err := kc.Read(kcfile); err != nil {
		return err
	}

	if params != nil {
		kc.Merge(params)
	} else {
		kc.Merge(k.Params)
	}

	if err := kc.Write(kcfile); err != nil {
		return err
	}

	// Prepare kernel headers.
	if err := sh.Run("make", "-C", k.Directory(), "olddefconfig", "prepare"); err != nil {
		return err
	}

	if mg.Verbose() {
		fmt.Println("Successfully configured", k.Name())
	}

	return nil
}
