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
func NewDomainList() *DomainList {
	return &DomainList{
		s: make(map[[16]byte]struct{}),
		m: make(map[[32]byte]struct{}),
		l: make(map[[256]byte]struct{}),
	}
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

func loadGeoSiteData(path string, domains []string) (*DomainList, error) {
	include := NewDomainList()
	geositeData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	geosite := new(router.GeoSiteList)
	if err := proto.Unmarshal(geositeData, geosite); err != nil {
		return nil, err
	}
	for _, domain := range domains {
		rules, err := parseDomainRule(geosite, domain)
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			if !include.Has(rule.Value) {
				include.Add(rule.Value)

			}
		}

	}
	return include, nil

}

func parseDomainRule(geosite *router.GeoSiteList, domain string) ([]*router.Domain, error) {
	var domains []*router.Domain
	if strings.HasPrefix(domain, "geosite:") {
		country := strings.ToUpper(domain[8:])
		for _, entry := range geosite.GetEntry() {
			if country == entry.GetCountryCode() {
				domains = append(domains, entry.GetDomain()...)
			}
		}
	}
	if strings.HasPrefix(domain, "domain:") {
		domains = append(domains, &router.Domain{
			Type:      router.Domain_Domain,
			Value:     domain[7:],
			Attribute: nil,
		})
	}
	return domains, nil
}
