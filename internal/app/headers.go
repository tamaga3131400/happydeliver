package app

import "github.com/gin-gonic/gin"

// securityHeaders adds browser security headers to every response.
// The Content-Security-Policy for the web interface is set where the page is served.
func securityHeaders(c *gin.Context) {
	h := c.Writer.Header()
	h.Set("Strict-Transport-Security", "max-age=31536000")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
}
