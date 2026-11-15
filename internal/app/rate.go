package app

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type requestWindow struct {
	mu    sync.Mutex
	start time.Time
	hits  map[string]uint
}

func (w *requestWindow) allow(key string, period time.Duration, limit uint) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if w.start.IsZero() || now.Sub(w.start) >= period {
		w.start, w.hits = now, make(map[string]uint)
	}
	value, exists := w.hits[key]
	if value >= limit || (!exists && len(w.hits) >= 10000) {
		return false
	}
	w.hits[key] = value + 1
	return true
}

func publicRateLimit(limit func() uint) gin.HandlerFunc {
	window := &requestWindow{}
	return func(c *gin.Context) {
		max := limit()
		if max > 0 && !window.allow(c.ClientIP(), 2*time.Second, 2*max) {
			c.Header("Retry-After", "2")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate_limit_exceeded", "message": "Too many requests. Try again in 2 seconds.",
			})
		}
	}
}

// toolsRateLimit allows 20 network checks per minute and client IP.
func toolsRateLimit() gin.HandlerFunc {
	window := &requestWindow{}
	return func(c *gin.Context) {
		if !window.allow(c.ClientIP(), time.Minute, 20) {
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"message": [2]string{
				"Too many checks. Please wait a minute.", "Zu viele Prüfungen. Bitte warte eine Minute."}})
		}
	}
}
