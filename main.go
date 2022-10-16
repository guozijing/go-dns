package main

import "github.com/guozijing/go-dns/dns_req"

func main() {
	dns_req.DigDN("10.248.2.5:53", "www.baidu.com")
}
