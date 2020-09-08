package bypass

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyfile"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/parse"
	pkgtls "github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/coredns/coredns/plugin/pkg/transport"
)

var once sync.Once

func init() {
	caddy.RegisterPlugin("bypass", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	b, err := parseBypass(c)
	if err != nil {
		return plugin.Error("bypass", err)
	}
	if b.LenPass() > max {
		return plugin.Error("bypass", fmt.Errorf("more than %d TOs configured: %d", max, b.LenPass()))
	}

	if b.LenForward() > max {
		return plugin.Error("bypass", fmt.Errorf("more than %d TOs configured: %d", max, b.LenForward()))
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		b.Next = next
		return b
	})

	c.OnStartup(func() error {
		return b.OnStartup()
	})

	c.OnShutdown(func() error {
		return b.OnShutdown()
	})
	once.Do(func() {
		caddy.RegisterEventHook("reload", b.hook)
	})

	return nil
}

// OnStartup starts a goroutines for all proxies.
func (b *Bypass) OnStartup() (err error) {
	for _, p := range b.forward {
		p.start(b.hcInterval)
	}
	for _, p := range b.pass {
		p.start(b.hcInterval)

	}
	return nil
}

// OnShutdown stops all configured proxies.
func (b *Bypass) OnShutdown() error {
	for _, p := range b.forward {
		p.close()
	}
	for _, p := range b.pass {
		p.close()
	}
	b.quit <- true

	return nil
}

// Close is a synonym for OnShutdown().
func (b *Bypass) Close() { b.OnShutdown() }

func parseBypass(c *caddy.Controller) (*Bypass, error) {
	var (
		b   *Bypass
		err error
		i   int
	)
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++
		b, err = ParseBypassStanza(&c.Dispenser)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// ParseBypassStanza parses one forward stanza
func ParseBypassStanza(c *caddyfile.Dispenser) (*Bypass, error) {
	b := New()

	if !c.Args(&b.from) {
		return b, c.ArgErr()
	}
	b.from = plugin.Host(b.from).Normalize()

	to := c.RemainingArgs()
	if len(to) == 0 {
		return b, c.ArgErr()
	}

	toHosts, err := parse.HostPortOrFile(to...)
	if err != nil {
		return b, err
	}

	transports := make([]string, len(toHosts))
	for i, host := range toHosts {
		trans, h := parse.Transport(host)
		p := NewProxy(h, trans)
		b.pass = append(b.pass, p)
		transports[i] = trans
	}

	for c.NextBlock() {
		if err := parseBlock(c, b); err != nil {
			return b, err
		}
	}

	if b.tlsServerName != "" {
		b.tlsConfig.ServerName = b.tlsServerName
	}
	for i := range b.pass {
		// Only set this for proxies that need it.
		if transports[i] == transport.TLS {
			b.pass[i].SetTLSConfig(b.tlsConfig)
		}
		b.pass[i].SetExpire(b.expire)
	}
	for i := range b.forward {
		// Only set this for proxies that need it.
		if transports[i] == transport.TLS {
			b.forward[i].SetTLSConfig(b.tlsConfig)
		}
		b.forward[i].SetExpire(b.expire)

	}
	return b, nil
}

func parseBlock(c *caddyfile.Dispenser, b *Bypass) error {
	switch c.Val() {
	case "geosite":
		if !c.NextArg() {
			return c.ArgErr()

		}
		path := c.Val()
		if path == "" {
			return c.ArgErr()
		}
		_, err := os.Open(path)
		if err != nil {
			return err
		}
		b.geosite = path
	case "include":
		if !c.NextArg() {
			return c.ArgErr()
		}
		domain := c.Val()
		domains := strings.Split(domain, ",")
		file, err := os.Open(b.geosite)
		if err != nil {
			return err
		}
		defer file.Close()
		fileinfo, err := file.Stat()
		if err != nil {
			return err
		}
		domainList, err := NewDomainList(b.geosite, domains)
		if err != nil {
			return err
		}
		b.include = domainList
		csum, err := PartialChecksum(file, fileinfo.Size())
		if err != nil {
			return err
		}
		b.domainChecksum = string(csum)
		b.domains = domains
	case "forward":
		forward := c.RemainingArgs()
		if len(forward) == 0 {
			return c.ArgErr()
		}
		transports := make([]string, len(forward))
		for i, host := range forward {
			trans, h := parse.Transport(host)
			p := NewProxy(h, trans)
			b.forward = append(b.forward, p)
			transports[i] = trans
		}
	case "max_fails":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		if n < 0 {
			return fmt.Errorf("max_fails can't be negative: %d", n)
		}
		b.maxfails = uint32(n)
	case "health_check":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("health_check can't be negative: %d", dur)
		}
		b.hcInterval = dur
	case "force_tcp":
		if c.NextArg() {
			return c.ArgErr()
		}
		b.opts.forceTCP = true
	case "prefer_udp":
		if c.NextArg() {
			return c.ArgErr()
		}
		b.opts.preferUDP = true
	case "tls":
		args := c.RemainingArgs()
		if len(args) > 3 {
			return c.ArgErr()
		}

		tlsConfig, err := pkgtls.NewTLSConfigFromArgs(args...)
		if err != nil {
			return err
		}
		b.tlsConfig = tlsConfig
	case "tls_servername":
		if !c.NextArg() {
			return c.ArgErr()
		}
		b.tlsServerName = c.Val()
	case "expire":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("expire can't be negative: %s", dur)
		}
		b.expire = dur
	case "policy":
		if !c.NextArg() {
			return c.ArgErr()
		}
		switch x := c.Val(); x {
		case "random":
			b.p = &random{}
		case "round_robin":
			b.p = &roundRobin{}
		case "sequential":
			b.p = &sequential{}
		default:
			return c.Errf("unknown policy '%s'", x)
		}
	case "reload":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		if dur < 0 {
			return fmt.Errorf("reload duration can't be negative: %s", dur)
		}
		b.dur = dur

	default:
		return c.Errf("unknown property '%s'", c.Val())
	}

	return nil
}

const max = 15 // Maximum number of upstreams.
