package sysctl

import (
	"github.com/pkg/errors"

	sysctl "github.com/lorenzosaino/go-sysctl"
	log "github.com/sirupsen/logrus"
)

// Apply sets a given map of sysctls on the machine.
func Apply(ctls map[string]string, verbose bool) error {

	for ctl, v := range ctls {
		cur, err := sysctl.Get(ctl)
		if err != nil {
			return errors.Wrap(err, errSysctlGet)
		}

		if cur != v {
			err = sysctl.Set(ctl, v)
			if err != nil {
				return errors.Wrap(err, errSysctlSet)
			}

			if verbose {
				log.Infof("Applied sysctl %s=%s", ctl, v)
			}
		}
	}

	return nil
}
