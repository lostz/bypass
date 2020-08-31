package bypass

import (
	"context"
	"time"

	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/dnstap/msg"
	"github.com/coredns/coredns/request"

	tap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

func toDnstap(ctx context.Context, host string, b *Bypass, state request.Request, reply *dns.Msg, start time.Time) error {
	tapper := dnstap.TapperFromContext(ctx)
	if tapper == nil {
		return nil
	}
	// Query
	m := msg.New().Time(start).HostPort(host)
	opts := b.opts
	t := ""
	switch {
	case opts.forceTCP: // TCP flag has precedence over UDP flag
		t = "tcp"
	case opts.preferUDP:
		t = "udp"
	default:
		t = state.Proto()
	}

	if t == "tcp" {
		m.SocketProto = tap.SocketProtocol_TCP
	} else {
		m.SocketProto = tap.SocketProtocol_UDP
	}

	if tapper.Pack() {
		m.Msg(state.Req)
	}
	msg, err := m.ToOutsideQuery(tap.Message_FORWARDER_QUERY)
	if err != nil {
		return err
	}
	tapper.TapMessage(msg)

	// Response
	if reply != nil {
		if tapper.Pack() {
			m.Msg(reply)
		}
		m, err := m.Time(time.Now()).ToOutsideResponse(tap.Message_FORWARDER_RESPONSE)
		if err != nil {
			return err
		}
		tapper.TapMessage(m)
	}

	return nil
}
