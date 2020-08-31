package bypass

import (
	"testing"
	"time"
)

func TestLoadDomainListFromUrl(t *testing.T) {
	lists, err := NewDomainList("https://cdn.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/accelerated-domains.china.conf", 10*time.Second)
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Info(lists.Len())
}
