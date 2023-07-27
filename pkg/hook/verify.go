package hook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

func VerifySyncRequest(req *http.Request, ipNet net.IPNet, log logintf, secret string,
	header string, secretType string, signaturePrefix string) bool {
	var ip_check = verifyIP(req.RemoteAddr, ipNet, log)
	var secret_check = verifySecret(req, secret, header, secretType, signaturePrefix)
	log.V(3).Info("verifySyncRequest", "ip", req.RemoteAddr, "secret", secret, "header",
		header, "secretType", secretType, "signaturePrefix", signaturePrefix,
		"ipCheck", ip_check, "secret_check", secret_check)
	return ip_check && secret_check
}

func verifyIP(ipString string, ipNet net.IPNet, log logintf) bool {
	ip, err := extractIP(ipString)
	if err != nil {
		log.V(0).Error(err, "invalid ip address", "ip", ipString)
		return false
	}
	if ipNet.Contains(ip) {
		return true
	}
	return false

}

func extractIP(address string) (net.IP, error) {
	ip := net.ParseIP(address)
	if ip != nil {
		return ip, nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip = net.ParseIP(host)
	if ip != nil {
		return ip, nil
	}
	return nil, fmt.Errorf("invalid address: %s", address)

}

func verifySecret(req *http.Request, secret string, header string, secretType string, signaturePrefix string) bool {
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
	return verifySecret
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
