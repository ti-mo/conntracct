package sysctl

import (
	"fmt"

	sysctl "github.com/lorenzosaino/go-sysctl"
	log "github.com/sirupsen/logrus"
)

// Apply sets a given map of sysctls on the machine.
func Apply(ctls map[string]string, verbose bool) error {
	for ctl, v := range ctls {
		cur, err := sysctl.Get(ctl)
		if err != nil {
			return fmt.Errorf("error getting sysctl: %w", err)
		}

		if cur == v {
			continue
		}

		if err := sysctl.Set(ctl, v); err != nil {
			return fmt.Errorf("error setting sysctl: %w", err)
		}

		if verbose {
			log.Infof("Applied sysctl %s=%s", ctl, v)
		}
	}

	return nil
}
