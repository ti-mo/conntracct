// +build mage

package main

import (
	"fmt"
	"os/user"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Integration is the namespace for all integration tests.
type Integration mg.Namespace

const (
	intCov = "test/output/integration.cover"
)

// Test runs integration tests requiring root.
func (Integration) Test() error {

	testArgs := []string{"test", "-v", "-race", "-coverprofile=" + intCov, "-covermode=atomic", "-tags=integration", "./..."}
	// Execute with sudo when the current UID is not 0.
	if u, _ := user.Current(); u.Uid != "0" {
		fmt.Println("Not running with uid 0, using sudo to run integration tests.")
		testArgs = append(testArgs, "-exec=sudo")
	}

	if err := sh.RunV("go", testArgs...); err != nil {
		return err
	}

	return nil
}

// Coverhtml runs the integration tests and opens the coverage report in the browser.
func (Integration) Coverhtml() error {

	mg.Deps(Integration.Test)

	if err := sh.RunV("go", "tool", "cover", "-html="+intCov); err != nil {
		return err
	}

	return nil
}

func (Integration) Dev() error {
	fmt.Println("Hot-running integration tests with modd..")
	if err := sh.RunV("modd", "-f", "modd-integration.conf"); err != nil {
		return err
	}

	return nil
}
