package ms_authorization_go

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type Authorizer struct {
	Certs map[string]string
}

func NewAuthenticator() *Authorizer {
	var certs map[string]string
	res, err := http.Get(CertsAPIEndpoint)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil
	}
	json.Unmarshal(data, &certs)

	return &Authorizer{
		Certs: certs,
	}
}

func (a *Authorizer) TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("Authorization")
		values := strings.Split(token, "Bearer ")
		if token == "" || len(values) != 2 {
			respondWithError(c, 401, "API token required")
			return
		}
		token = values[1]
		correct, id := a.verifyIDToken(token)
		if !correct {
			respondWithError(c, 401, "Invalid API token")
			return
		}
		c.Set("userId", id)
		c.Next()
	}
}

func (a *Authorizer) BackAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("Authorization")
		values := strings.Split(token, "Bearer ")
		if token == "" || len(values) != 2 {
			respondWithError(c, 401, "API token required")
			return
		}
		token = values[1]
		if token != os.Getenv("BACKEND_TOKEN") {
			respondWithError(c, 401, "Invalid API token")
			return
		}
		c.Next()
	}
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

func respondWithError(c *gin.Context, code int, message interface{}) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}

var CertsAPIEndpoint = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

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

func (a *Authorizer) verifyIDToken(token string) (bool, string) {
	claims, ok := a.verifyJWT(token)
	if !ok {
		log.Printf("error verifying ID token")
		return false, ""
	}
	userId := claims["user_id"]
	if userId == nil {
		log.Printf("error verifying ID token")
		return false, ""
	}

	return true, userId.(string)
}

func verifyPayload(t *jwt.Token) (claims jwt.MapClaims, ok bool) {
	projectID := os.Getenv("GOOGLE_PROJECT_ID")
	claims, ok = t.Claims.(jwt.MapClaims)
	if !ok {
		return
	}
	// Verify User
	claimsAud, ok := claims["aud"].(string)
	if claimsAud != projectID || !ok {
		ok = false
		return
	}
	// Verify issued at
	iss := "https://securetoken.google.com/" + projectID
	claimsIss, ok := claims["iss"].(string)
	if claimsIss != iss || !ok {
		return
	}
	// sub is uid of user.
	_, ok = claims["sub"].(string)
	if !ok {
		return
	}
	return
}

func readPublicKey(cert []byte) (*rsa.PublicKey, error) {
	publicKeyBlock, _ := pem.Decode(cert)
	if publicKeyBlock == nil {
		return nil, errors.New("invalid public key data")
	}
	if publicKeyBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid public key type: %s", publicKeyBlock.Type)
	}
	c, err := x509.ParseCertificate(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}
	return publicKey, nil
}

func (a *Authorizer) verifyJWT(t string) (claims jwt.MapClaims, ok bool) {
	parsed, _ := jwt.Parse(t, func(t *jwt.Token) (interface{}, error) {
		cert, _ := a.GetCertificateFromToken(t)
		publicKey, err := readPublicKey(cert)
		if err != nil {
			return "", err
		}
		return publicKey, nil
	})

	ok = parsed.Valid
	if !ok {
		return
	}
	if parsed.Header["alg"] != "RS256" {
		ok = false
		return
	}
	claims, ok = verifyPayload(parsed)
	return
}
