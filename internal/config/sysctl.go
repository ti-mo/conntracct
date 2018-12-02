package config

import (
	sysctl "github.com/lorenzosaino/go-sysctl"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// configureSysctl sets sysctls on the machine that are required
// for conntracct to work.
func applySysctl(ctls map[string]string) error {

	for ctl, v := range ctls {
		acct, err := sysctl.Get(ctl)
		if err != nil {
			return errors.Wrap(err, errGetSysctl)
		}

		if acct != "1" {
			err = sysctl.Set(ctl, v)
			if err != nil {
				return errors.Wrap(err, errSetSysctl)
			}
			log.Infof("Applied sysctl %s=%s", ctl, v)
		}
	}

	return nil
}
