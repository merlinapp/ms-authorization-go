package authorization

import (
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)


func TestAuthorizer_GinAPIAuthMiddleware(t *testing.T) {

	var test = []struct {
		ServerApiKey string
		RequestApiKey string
		CodeExpected int
		ShouldCalled bool
	} {
		{"12345", "12345", http.StatusOK, true},
		{"12345", "899889", http.StatusUnauthorized, false},
		{"12345", "", http.StatusUnauthorized, false},

	}

	for _, tc := range test {
		performGinTest(t, tc.ServerApiKey, tc.RequestApiKey,tc.CodeExpected, tc.ShouldCalled)
	}
}

func performGinTest(t *testing.T, serverApiKey,requestApiKey  string,codeExpected int, shouldCalled bool) {

	auth := NewAuthenticator()
	called := false

	router := gin.Default()
	router.Use(auth.GinAPIAuthMiddleware(serverApiKey))
	router.GET("/", func(c *gin.Context) {
		called = true
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set(ApiKey, requestApiKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, shouldCalled,called)
	assert.Equal(t, codeExpected, w.Code)

	allowHeaders := w.Header().Get(AccessControlAllowHeaders)
	containsApiKeyHeaders := strings.Contains(allowHeaders, ApiKeyHeader)
	assert.True(t,containsApiKeyHeaders)
}


func TestAuthorizer_APIAuthMiddleware(t *testing.T) {
	var test = []struct {
		ServerApiKey string
		RequestApiKey string
		CodeExpected int
		ShouldCalled bool
	} {
		{"12345", "12345", http.StatusOK, true},
		{"12345", "899889", http.StatusUnauthorized, false},
		{"12345", "", http.StatusUnauthorized, false},
	}

	for _, tc := range test {
		performHTTPTest(t, tc.ServerApiKey, tc.RequestApiKey,tc.CodeExpected, tc.ShouldCalled)
	}
}

func performHTTPTest(t *testing.T, serverApiKey, requestApiKey string, expectedCode int, shouldCalled bool) {

	called := false
	auth := NewAuthenticator()

	handler := func(w http.ResponseWriter, r *http.Request)  {
		called = true
	}
	handlerTest := http.HandlerFunc(handler)
	httHandler := auth.APIAuthMiddleware(handlerTest, serverApiKey)

	req := httptest.NewRequest("GET", "/", nil)

	req.Header.Set(ApiKey, requestApiKey)
	w := httptest.NewRecorder()
	httHandler.ServeHTTP(w, req)

	resp := w.Result()

	assert.Equal(t, shouldCalled, called)
	assert.Equal(t, expectedCode, resp.StatusCode)

	allowHeaders := resp.Header.Get(AccessControlAllowHeaders)
	containsApiKeyHeaders := strings.Contains(allowHeaders, ApiKeyHeader)
	assert.True(t,containsApiKeyHeaders)
}

