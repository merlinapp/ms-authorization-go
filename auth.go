package authorization

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type Auth interface {
	GinTokenAuthMiddleware() gin.HandlerFunc
	GinTokenAndBackAuthMiddleware() gin.HandlerFunc
	GinBackAuthMiddleware() gin.HandlerFunc

	TokenAuthMiddleware(h http.Handler) http.Handler
	TokenAndBackAuthMiddleware(h http.Handler) http.Handler
	BackAuthMiddleware(h http.Handler) http.Handler
}
