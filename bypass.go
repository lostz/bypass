package bypass

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/debug"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("bypass")

//Bypass ...
type Bypass struct {
	concurrent int64 // atomic counters need to be first in struct for proper alignment

	pass       []*Proxy
	forward    []*Proxy
	p          Policy
	hcInterval time.Duration
	geosite    string
	domains    []string
	include    *DomainList

	from           string
	domainChecksum string
	dur            time.Duration

	opts options // also here for testing

	tlsConfig     *tls.Config
	tlsServerName string
	maxfails      uint32
	expire        time.Duration
	maxConcurrent int64

	// ErrLimitExceeded indicates that a query was rejected because the number of concurrent queries has exceeded
	// the maximum allowed (maxConcurrent)
	ErrLimitExceeded error

	Next plugin.Handler
	quit chan bool
}

// New returns a new Bypass.
func New() *Bypass {
	b := &Bypass{maxfails: 2, tlsConfig: new(tls.Config), expire: defaultExpire, p: new(random), from: ".", hcInterval: hcInterval, quit: make(chan bool), dur: defaultDuraiton, opts: options{forceTCP: false, preferUDP: false, hcRecursionDesired: true}}
	return b
}

// SetPass appends p to the proxy list and starts healthchecking.
func (b *Bypass) SetPass(p *Proxy) {
	b.pass = append(b.pass, p)
	p.start(b.hcInterval)
}

// SetForward appends p to the proxy list and starts healthchecking.
func (b *Bypass) SetForward(p *Proxy) {
	b.forward = append(b.forward, p)
	p.start(b.hcInterval)
}

// LenPass returns the number of configured proxies.
func (b *Bypass) LenPass() int { return len(b.pass) }

// LenForward returns the number of configured proxies.
func (b *Bypass) LenForward() int { return len(b.forward) }

// Name implements plugin.Handler.
func (b *Bypass) Name() string { return "bypass" }

// ServeDNS implements plugin.Handler.
func (b *Bypass) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	match := b.match(state)
	if b.maxConcurrent > 0 {
		count := atomic.AddInt64(&(b.concurrent), 1)
		defer atomic.AddInt64(&(b.concurrent), -1)
		if count > b.maxConcurrent {
			MaxConcurrentRejectCount.Add(1)
			return dns.RcodeServerFailure, b.ErrLimitExceeded
		}
	}
	fails := 0
	var upstreamErr error
	i := 0
	var list []*Proxy
	if match {
		list = b.ListPass()
	} else {
		list = b.ListForward()
	}
	deadline := time.Now().Add(defaultTimeout)
	start := time.Now()
	for time.Now().Before(deadline) {
		if i >= len(list) {
			// reached the end of list, reset to begin
			i = 0
			fails = 0
		}

		proxy := list[i]
		i++
		if proxy.Down(b.maxfails) {
			fails++
			if fails < len(list) {
				continue
			}
			// All upstream proxies are dead, assume healthcheck is completely broken and randomly
			// select an upstream to connect to.
			r := new(random)
			proxy = r.List(list)[0]

			HealthcheckBrokenCount.Add(1)
		}

		var (
			ret *dns.Msg
			err error
		)
		opts := b.opts
		for {
			ret, err = proxy.Connect(ctx, state, opts)
			if err == ErrCachedClosed { // Remote side closed conn, can only happen with TCP.
				continue
			}
			// Retry with TCP if truncated and prefer_udp configured.
			if ret != nil && ret.Truncated && !opts.forceTCP && opts.preferUDP {
				opts.forceTCP = true
				continue
			}
			break
		}

		taperr := toDnstap(ctx, proxy.addr, b, state, ret, start)

		upstreamErr = err

		if err != nil {
			// Kick off health check to see if *our* upstream is broken.
			if b.maxfails != 0 {
				proxy.Healthcheck()
			}

			if fails < len(list) {
				continue
			}
			break
		}

		// Check if the reply is correct; if not return FormErr.
		if !state.Match(ret) {
			debug.Hexdumpf(ret, "Wrong reply for id: %d, %s %d", ret.Id, state.QName(), state.QType())

			formerr := new(dns.Msg)
			formerr.SetRcode(state.Req, dns.RcodeFormatError)
			w.WriteMsg(formerr)
			return 0, taperr
		}

		w.WriteMsg(ret)
		return 0, taperr
	}

	if upstreamErr != nil {
		return dns.RcodeServerFailure, upstreamErr
	}

	return dns.RcodeServerFailure, ErrNoHealthy

}

func (b *Bypass) match(state request.Request) bool {
	if !plugin.Name(b.from).Matches(state.Name()) || !b.isAllowedDomain(state.Name()) {
		return false
	}
	return true
}

func (b *Bypass) isAllowedDomain(name string) bool {
	if dns.Name(name) == dns.Name(b.from) {
		return true
	}
	return b.include.Has(name)
}

// ForceTCP returns if TCP is forced to be used even when the request comes in over UDP.
func (b *Bypass) ForceTCP() bool { return b.opts.forceTCP }

// PreferUDP returns if UDP is preferred to be used even when the request comes in over TCP.
func (b *Bypass) PreferUDP() bool { return b.opts.preferUDP }

func (b *Bypass) hook(event caddy.EventName, info interface{}) error {
	if event != caddy.InstanceStartupEvent {
		return nil
	}
	file, err := os.Open(b.geosite)
	if err != nil {
		return err
	}
	defer file.Close()
	fileinfo, err := file.Stat()
	if err != nil {
		return err
	}
	csum, err := PartialChecksum(file, fileinfo.Size())
	if err != nil {
		return err
	}
	log.Infof("Running domainList  sum = %x\n", string(csum))
	go func() {
		tick := time.NewTicker(b.dur)
		for {
			select {
			case <-tick.C:
				file, err := os.Open(b.geosite)
				if err != nil {
					continue
				}
				defer file.Close()
				fileinfo, err := file.Stat()
				if err != nil {
					continue
				}
				_, err = PartialChecksum(file, fileinfo.Size())
				if err != nil {
					continue
				}
				if string(csum) != b.domainChecksum {
					include, err := loadGeoSiteData(b.geosite, b.domains)
					if err != nil {
						continue
					}
					b.include = include
					b.domainChecksum = string(csum)
					log.Infof("Finish update domainlist size: %d", include.Len())
				}
			case <-b.quit:
				return

			}

		}
	}()

	return nil

}

var (
	// ErrNoHealthy means no healthy proxies left.
	ErrNoHealthy = errors.New("no healthy proxies")
	// ErrNoForward means no forwarder defined.
	ErrNoForward = errors.New("no forwarder defined")
	// ErrCachedClosed means cached connection was closed by peer.
	ErrCachedClosed = errors.New("cached connection was closed by peer")
)

// options holds various options that can be set.
type options struct {
	forceTCP           bool
	preferUDP          bool
	hcRecursionDesired bool
}

const defaultTimeout = 5 * time.Second
const defaultDuraiton = 86400 * time.Second

// ListPass returns a set of proxies to be used for this client depending on the policy in f.
func (b *Bypass) ListPass() []*Proxy { return b.p.List(b.pass) }

// ListForward returns a set of proxies to be used for this client depending on the policy in f.
func (b *Bypass) ListForward() []*Proxy { return b.p.List(b.forward) }
