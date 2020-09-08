package bypass

import (
	"io/ioutil"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
	"v2ray.com/core/app/router"
)

//DomainList ...
type DomainList struct {
	s map[[16]byte]struct{}
	m map[[32]byte]struct{}
	l map[[256]byte]struct{}
}

//NewDomainList ...
func NewDomainList(path string, targets []string) (*DomainList, error) {

	d := &DomainList{
		s: make(map[[16]byte]struct{}),
		m: make(map[[32]byte]struct{}),
		l: make(map[[256]byte]struct{}),
	}
	geositeBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var geositeList router.GeoSiteList
	if err := proto.Unmarshal(geositeBytes, &geositeList); err != nil {
		return nil, err
	}
	for _, target := range targets {
		var country string
		if strings.HasPrefix(target, "geosite:") {
			country = strings.ToUpper(target[8:])
		}
		for _, site := range geositeList.Entry {
			if site.CountryCode == country {
				for _, domain := range site.Domain {
					d.Add(dns.Fqdn(domain.Value))
				}

			}
		}
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

//Has ...
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

//Len ...
func (l *DomainList) Len() int {
	return len(l.l) + len(l.m) + len(l.s)
}
