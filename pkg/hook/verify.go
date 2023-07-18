package hook

import (
	"net"
	"net/http"
)

func VerifySyncRequest(req *http.Request, ipNet net.IPNet, log logintf) bool {
	log.V(2).Info(req.RemoteAddr)
	return verifyIP(req.RemoteAddr, ipNet)
}

func verifyIP(ipString string, ipNet net.IPNet) bool {
	ip := net.ParseIP(ipString)
	if ip != nil {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false

}
