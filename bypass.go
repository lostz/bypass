package bypass

import (
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("bypass")

//Bypass ...
type Bypass struct {
}
