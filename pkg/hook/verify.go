package hook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

func VerifySyncRequest(req *http.Request, ipNet net.IPNet, log logintf, secret string,
	header string, secretType string, signaturePrefix string) bool {
	log.V(2).Info(req.RemoteAddr)
	verifySecret := true
	if secret != "" {
		headerSecret := req.Header.Get(header)
		if headerSecret == "" {
			return false
		}
		switch secretType {
		case "token":
			{
				verifySecret = verifyToken(secret, headerSecret)
			}
		case "signature":
			{
				body, err := ioutil.ReadAll(req.Body)
				if err != nil || string(body) == "" {
					return false
				}
				verifySecret = verifySignature(secret, headerSecret, body, signaturePrefix)
			}
		}

	}
	return verifyIP(req.RemoteAddr, ipNet) && verifySecret
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

func verifyToken(secret string, value string) bool {
	return strings.Compare(secret, value) == 0
}

func verifySignature(secret string, signature string, body []byte, prefix string) bool {
	secretBytes := []byte(secret)
	hasher := hmac.New(sha256.New, secretBytes)
	hasher.Write(body)
	calculatedSignature := prefix + hex.EncodeToString(hasher.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(calculatedSignature))
}
