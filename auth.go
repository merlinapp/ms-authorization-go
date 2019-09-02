package authorization

import (
	"github.com/gin-gonic/gin"
)

type Auth interface {
	TokenAuthMiddleware() gin.HandlerFunc
	TokenAndBackAuthMiddleware() gin.HandlerFunc
	BackAuthMiddleware() gin.HandlerFunc
}
