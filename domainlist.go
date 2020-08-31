package bypass

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

//DomainList ...
type DomainList struct {
	s map[[16]byte]struct{}
	m map[[32]byte]struct{}
	l map[[256]byte]struct{}
}

//NewDomainList ...
func NewDomainList(listURL string, timeout time.Duration) (*DomainList, error) {
	c := &http.Client{
		Timeout: timeout,
	}
	resp, err := c.Get(listURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %v", resp.StatusCode)
	}

	d := &DomainList{
		s: make(map[[16]byte]struct{}),
		m: make(map[[32]byte]struct{}),
		l: make(map[[256]byte]struct{}),
	}
	s := bufio.NewScanner(resp.Body)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		//ignore lines begin with # and empty lines
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		fqdn := dns.Fqdn(line)
		if _, ok := dns.IsDomainName(fqdn); !ok {
			return nil, fmt.Errorf("invaild domain [%s]", line)
		}
		d.Add(fqdn)
	}
	return d, nil
}

//Add ...
func (l *DomainList) Add(fqdn string) {
	n := len(fqdn)

	switch {
	case n <= 16:
		var b [16]byte
		copy(b[:], fqdn)
		l.s[b] = struct{}{}
	case n <= 32:
		var b [32]byte
		copy(b[:], fqdn)
		l.m[b] = struct{}{}
	default:
		var b [256]byte
		copy(b[:], fqdn)
		l.l[b] = struct{}{}
	}
}

func (l *DomainList) Has(fqdn string) bool {
	if fqdn == "." {
		return false
	}
	idx := make([]int, 1, 6)
	off := 0
	end := false

	for {
		off, end = dns.NextLabel(fqdn, off)
		if end {
			break
		}
		idx = append(idx, off)
	}

	for i := range idx {
		p := idx[len(idx)-1-i]
		if l.has(fqdn[p:]) {
			return true
		}
	}
	return false
}

func (l *DomainList) has(fqdn string) bool {
	n := len(fqdn)
	switch {
	case n <= 16:
		var b [16]byte
		copy(b[:], fqdn)
		_, ok := l.s[b]
		return ok
	case n <= 32:
		var b [32]byte
		copy(b[:], fqdn)
		_, ok := l.m[b]
		return ok
	default:
		var b [256]byte
		copy(b[:], fqdn)
		_, ok := l.l[b]
		return ok
	}
}

func (l *DomainList) Len() int {
	return len(l.l) + len(l.m) + len(l.s)
}
