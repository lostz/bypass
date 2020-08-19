package bypass

import (
	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("forward", setup) }

func setup(c *caddy.Controller) error {

	return nil
}

// OnStartup starts a goroutines for all proxies.
func (p *Bypass) OnStartup() (err error) {
	return nil
}

// OnShutdown stops all configured proxies.
func (p *Bypass) OnShutdown() error {
	return nil
}
