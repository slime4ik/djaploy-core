package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func JWTMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. take the access token. The main source is the httpOnly cookie set by the OAuth
		//    callback; Bearer and query are fallbacks for API clients and websockets.
		tokenString, err := c.Cookie("access_token")
		if err != nil || tokenString == "" {
			tokenString = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		}
		if tokenString == "" {
			tokenString = c.Query("token") // for ws
		}
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "токен не передан"})
			return
		}

		// 2. parse and ALWAYS verify the signing method, otherwise alg:none and algorithm
		//    swapping attacks work
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "невалидный токен"})
			return
		}

		// 3. user_id (the tag in AccessClaims is "user_id")
		userID, _ := claims["user_id"].(string)
		if userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "в токене нет user_id"})
			return
		}

		c.Set("user_id", userID)
		c.Next()
	}
}
