package authorization

import (
	"context"
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

const (
	ApiKey = "Api-Key"
)

type Authorizer struct {
	Certs map[string]string
}

func NewAuthenticator() Auth {
	var certs map[string]string
	res, err := http.Get(CertsAPIEndpoint)
	if err != nil {
		return &Authorizer{}
	}
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return &Authorizer{}
	}
	json.Unmarshal(data, &certs)

	return &Authorizer{
		Certs: certs,
	}
}

func (a *Authorizer) TokenAuthMiddleware(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		token, ok := getToken(r.Header)
		if !ok {
			respondWithError(w, http.StatusUnauthorized, "API token required")
			return
		}
		correct, userId, userRole := a.verifyIDToken(token)
		if !correct {
			respondWithError(w, http.StatusUnauthorized, "Invalid API Token")
			return
		}
		ctx := context.WithValue(r.Context(), "userId", userId)
		ctx = context.WithValue(ctx, "role", userRole)

		h.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

// Deprecated, use TokenAndApiKey
func (a *Authorizer) TokenAndBackAuthMiddleware(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		token, ok := getToken(r.Header)
		if !ok {
			respondWithError(w, http.StatusUnauthorized, "API token required")
			return
		}
		hasBackendToken := token == os.Getenv("BACKEND_TOKEN")
		if hasBackendToken {
			h.ServeHTTP(w, r)
		} else if correct, userId, userRole := a.verifyIDToken(token); correct {
			ctx := context.WithValue(r.Context(), "userId", userId)
			ctx = context.WithValue(ctx, "role", userRole)
			h.ServeHTTP(w, r.WithContext(ctx))
		} else {
			respondWithError(w, http.StatusUnauthorized, "Invalid API Token")
			return
		}

	}
	return http.HandlerFunc(fn)
}

func (a *Authorizer) TokenAndApiKey(h http.Handler, apiKey string) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		token, isToken := getToken(r.Header)

		if isToken && a.isValidToken(token) {
			_, userId, userRole := a.verifyIDToken(token)
			ctx := context.WithValue(r.Context(), "userId", userId)
			ctx = context.WithValue(ctx, "role", userRole)
			h.ServeHTTP(w, r.WithContext(ctx))
		} else if isApiKey(r.Header, apiKey) {
			h.ServeHTTP(w, r)
		} else {
			respondWithError(w, http.StatusUnauthorized, "Permission denied")
			return
		}
	}
	return http.HandlerFunc(fn)
}

func (a *Authorizer) isValidToken(token string) bool {
	isValid, _, _ := a.verifyIDToken(token)
	return isValid
}

func (a *Authorizer) BackAuthMiddleware(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		token, ok := getToken(r.Header)
		if !ok {
			respondWithError(w, http.StatusUnauthorized, "API token required")
			return
		}
		hasBackendToken := token == os.Getenv("BACKEND_TOKEN")
		if !hasBackendToken {
			respondWithError(w, http.StatusUnauthorized, "Invalid API Token")
			return
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (a *Authorizer) GinTokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := getToken(c.Request.Header)
		if !ok {
			ginRespondWithError(c, http.StatusUnauthorized, "API token required")
			return
		}
		correct, userId, userRole := a.verifyIDToken(token)
		if !correct {
			ginRespondWithError(c, http.StatusUnauthorized, "Invalid API token")
			return
		}
		c.Set("userId", userId)
		c.Set("role", userRole)
		c.Next()
	}
}

func (a *Authorizer) GinTokenAndBackAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := getToken(c.Request.Header)
		if !ok {
			ginRespondWithError(c, http.StatusUnauthorized, "API token required")
			return
		}
		hasBackendToken := token == os.Getenv("BACKEND_TOKEN")
		if hasBackendToken {
			c.Next()
		} else if correct, userId, userRole := a.verifyIDToken(token); correct {
			c.Set("userId", userId)
			c.Set("role", userRole)
			c.Next()
		} else {
			ginRespondWithError(c, http.StatusUnauthorized, "Invalid API token")
			return
		}
	}
}

func (a *Authorizer) GinBackAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := getToken(c.Request.Header)
		if !ok {
			ginRespondWithError(c, http.StatusUnauthorized, "API token required")
			return
		}
		hasBackendToken := token == os.Getenv("BACKEND_TOKEN")
		if hasBackendToken {
			c.Next()
		} else {
			ginRespondWithError(c, http.StatusUnauthorized, "Invalid API token")
			return
		}
	}
}

func (a *Authorizer) GinAPIAuthMiddleware(apiKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKeyValue := c.Request.Header.Get(ApiKeyHeader)
		addGinAPIHeader(c)
		if apiKeyValue == "" {
			ginRespondWithError(c, http.StatusUnauthorized, ApiKeyRequired)
			return
		}
		hasAPIKey := apiKeyValue == apiKey
		if hasAPIKey {
			c.Next()

		} else {
			ginRespondWithError(c, http.StatusUnauthorized, ApiKeyInvalid)
			return
		}
	}
}

func addGinAPIHeader(c *gin.Context) {

	hs := c.Writer.Header()
	allow := hs.Get(AccessControlAllowHeaders)

	value := ""
	if len(allow) == 0 {
		value = ApiKeyHeader
	} else {
		value = fmt.Sprintf("%s,%s", allow, ApiKeyHeader)
	}

	hs.Set(AccessControlAllowHeaders, value)
}

func (a *Authorizer) APIAuthMiddleware(h http.Handler, apiKey string) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		apiKeyHeader := r.Header.Get(ApiKeyHeader)

		allow := w.Header().Get(AccessControlAllowHeaders)
		value := ""
		if len(allow) == 0 {
			value = ApiKeyHeader
		} else {
			value = fmt.Sprintf("%s,%s", allow, ApiKeyHeader)
		}
		w.Header().Set(AccessControlAllowHeaders, value)

		if apiKeyHeader == "" {
			respondWithError(w, http.StatusUnauthorized, ApiKeyRequired)
			return
		}
		hasApiKey := apiKeyHeader == apiKey
		if !hasApiKey {
			respondWithError(w, http.StatusUnauthorized, ApiKeyInvalid)
			return
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
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

func (a *Authorizer) verifyIDToken(token string) (bool, string, string) {
	claims, ok := a.verifyJWT(token)

	if !ok {
		log.Printf("error verifying ID token")
		return false, "", ""
	}

	userId := claims["user_id"]
	if userId == nil {
		log.Printf("error verifying ID token")
		return false, "", ""
	}

	userRole := claims["role"]
	if userRole == nil {
		log.Printf("user role not found for user %s, with token %s", userId, token)
		return true, userId.(string), "NO_ROLE"
	}

	return true, userId.(string), userRole.(string)
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

func isApiKey(headers http.Header, apiKey string) bool {
	apiKeyValue := headers.Get(ApiKeyHeader)
	if apiKeyValue == "" {
		return false
	}
	if apiKeyValue != apiKey {
		return false
	}
	return true
}

func getToken(headers http.Header) (string, bool) {
	token := headers.Get("Authorization")
	values := strings.Split(token, "Bearer ")
	if token == "" || len(values) != 2 {
		return "", false
	}
	return values[1], true
}

func ginRespondWithError(c *gin.Context, code int, message interface{}) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}

func respondWithError(w http.ResponseWriter, code int, message interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := make(map[string]interface{})
	err["error"] = message
	json.NewEncoder(w).Encode(err)
}
