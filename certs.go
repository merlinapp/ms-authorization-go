package authorization

import (
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"net/http"
)

var CertsAPIEndpoint = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

func (a *Authorizer) GetCertificateFromToken(token *jwt.Token) ([]byte, error) {

	// Get kid
	kid, ok := token.Header["kid"]
	if !ok {
		return []byte{}, errors.New("kid not found")
	}
	kidString, ok := kid.(string)
	if !ok {
		return []byte{}, errors.New("kid cast error to string")
	}
	return a.getCertificate(kidString), nil
}

func (a *Authorizer) downloadCertificates() {
	var certs map[string]string
	res, err := http.Get(CertsAPIEndpoint)
	if err != nil {
		return
	}
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}
	json.Unmarshal(data, &certs)
	a.Certs = certs
}

func (a *Authorizer) getCertificates() (certs map[string]string) {
	return a.Certs
}

func (a *Authorizer) getCertificate(kid string) (cert []byte) {
	certs := a.getCertificates()
	certString, ok := certs[kid]
	if !ok {
		a.downloadCertificates()
		certs := a.getCertificates()
		certString = certs[kid]
	}
	cert = []byte(certString)
	return
}
