package bypass

import (
	"testing"
)

func TestLoadGeosite(t *testing.T) {
	domains, err := NewDomainList("./geosite.dat", []string{"geosite:apple-cn", "geosite:google-cn", "geosite:cn"})
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Info(domains.Len())
	found := domains.Has("baidu.com.")
	log.Info(found)
}
