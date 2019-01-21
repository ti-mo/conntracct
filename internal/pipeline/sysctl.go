package pipeline

import (
	"strconv"
	"sync"

	"github.com/lorenzosaino/go-sysctl"
	log "github.com/sirupsen/logrus"
)

var (
	warnOnce sync.Once

	SysctlWait = map[string]int{
		// TODO: UDP timeouts depend on the use case of the gateway,
		// give the user the chance to opt out of these warnings.

		"net/netfilter/nf_conntrack_tcp_timeout_close_wait": 15,
		"net/netfilter/nf_conntrack_tcp_timeout_fin_wait":   15,
		"net/netfilter/nf_conntrack_tcp_timeout_time_wait":  15,

		"net/netfilter/nf_conntrack_udp_timeout":        10,
		"net/netfilter/nf_conntrack_udp_timeout_stream": 30,
	}
)

func warnSysctl() {
	warnOnce.Do(func() {
		warnSysctlWait()
	})
}

func warnSysctlWait() {
	var warned bool

	for k, v := range SysctlWait {
		curStr, err := sysctl.Get(k)
		if err != nil {
			continue
		}
		cur, err := strconv.Atoi(curStr)
		if err != nil {
			continue
		}

		if cur > v {
			log.Warnf("sysctl %s is %d (recommended %d)", k, cur, v)
			warned = true
		}
	}

	if warned {
		log.Warn("Consider lowering the Conntrack connection timeouts above. Flows only generate destroy events when their timeout expires.")
	}
}
