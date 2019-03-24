package kernel

import (
	"fmt"
	"os"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// curl downloads the given URL to the given filePath.
// No-ops if the file already exists.
func curl(url, filePath string) error {

	// Skip if destination path already exists.
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		if mg.Verbose() {
			fmt.Printf("Downloading %s to %s..\n", url, filePath)
		}
		if err := sh.Run("curl", "-L", url, "-o", filePath); err != nil {
			return err
		}
	} else if mg.Verbose() {
		fmt.Println(filePath, "exists, skipping download.")
	}

	return nil
}

// unarchive extracts a gzip archive to a given directory.
// If path 'check' exists, the unarchive is skipped.
func unarchive(archive, dest, check string) error {

	// Skip if path already exists.
	if _, err := os.Stat(check); os.IsNotExist(err) {
		if mg.Verbose() {
			fmt.Printf("Extracting %s to %s..\n", archive, dest)
		}
		if err := sh.Run("tar", "xf", archive, "-C", dest); err != nil {
			return err
		}
		if mg.Verbose() {
			fmt.Printf("Extraction of %s complete!\n", archive)
		}
	} else if mg.Verbose() {
		fmt.Println(check, "exists, skipping unarchive.")
	}

	return nil
}

// trimExt removes .tar.gz and .tar.xz extensions from a string.
func trimExt(name string) string {

	name = strings.TrimSuffix(name, ".tar.gz")
	name = strings.TrimSuffix(name, ".tar.xz")

	return name
}
