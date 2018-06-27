package main

import (
	"github.com/shreddedbacon/openvpn-web-ui/lib"
	_ "github.com/shreddedbacon/openvpn-web-ui/routers"
	"github.com/astaxie/beego"
)

func main() {
	lib.AddFuncMaps()
	beego.Run()
}
