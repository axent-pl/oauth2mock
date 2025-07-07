package routing

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

func RateLimitMiddleware(rps float64, burst int) Middleware {
	limiter := rate.NewLimiter(rate.Limit(rps), burst)
	var mu sync.Mutex

	return func(next HandlerFunc) HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			ok := limiter.Allow()
			mu.Unlock()

			if !ok {
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}
			next(w, r)
		}
	}
}
