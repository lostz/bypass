package bypass

import (
	"os"
	"testing"
)

func TestLoadDomainListFromUrl(t *testing.T) {
	file, err := os.Open("./geosite.dat")
	if err != nil {
		log.Fatalf(err.Error())
	}
	defer file.Close()
	lists, err := NewDomainList(file, []string{"geosite:apple-cn", "geosite:google-cn", "geosite:cn"})
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Info(lists.Len())
}
