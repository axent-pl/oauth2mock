package routing

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/google/uuid"
)

// Types for routing and middleware
type route struct {
	method        string
	path          string
	postFormValue map[string]string
	queryValue    map[string]string
	handler       HandlerFunc
	middlewares   []Middleware
}

type HandlerFunc func(w http.ResponseWriter, r *http.Request)
type Middleware func(HandlerFunc) HandlerFunc

type Router struct {
	routes []*route
}

type RouteOption func(*route) error

// Route options
func WithPath(path string) RouteOption {
	return func(r *route) error {
		r.path = path
		return nil
	}
}

func WithMethod(method string) RouteOption {
	return func(r *route) error {
		r.method = method
		return nil
	}
}

func ForPostFormValue(key string, val string) RouteOption {
	return func(r *route) error {
		r.postFormValue[key] = val
		return nil
	}
}

func ForQueryValue(key string, val string) RouteOption {
	return func(r *route) error {
		r.queryValue[key] = val
		return nil
	}
}

// New: RouteOption to attach middlewares per-route
func WithMiddleware(mws ...Middleware) RouteOption {
	return func(r *route) error {
		r.middlewares = append(r.middlewares, mws...)
		return nil
	}
}

func (h *Router) RegisterHandler(handler HandlerFunc, options ...RouteOption) error {
	r := &route{
		handler:       handler,
		postFormValue: make(map[string]string),
		queryValue:    make(map[string]string),
	}
	for _, opt := range options {
		if err := opt(r); err != nil {
			return err
		}
	}
	h.routes = append(h.routes, r)
	return nil
}

// Match logic
func (r *route) matches(req *http.Request) bool {
	if len(r.method) > 0 && r.method != req.Method {
		return false
	}
	if len(r.path) > 0 && r.path != req.URL.Path {
		return false
	}
	queryParams := req.URL.Query()
	for key, val := range r.queryValue {
		if queryParams.Get(key) != val {
			return false
		}
	}
	if len(r.postFormValue) > 0 {
		for key, val := range r.postFormValue {
			if req.PostFormValue(key) != val {
				return false
			}
		}
	}
	return true
}

// ServeHTTP with per-route middleware chaining
func (h *Router) ServeHTTP(w http.ResponseWriter, routedRequest *http.Request) {
	ctx := context.WithValue(routedRequest.Context(), "RequestID", uuid.New().String())
	routedRequest = routedRequest.WithContext(ctx)

	dump, _ := httputil.DumpRequest(routedRequest, true)
	slog.Debug(string(dump))

	requestLogValue := RequestLogValue(routedRequest)

	slog.Info("request routing started", "request", requestLogValue)
	for _, route := range h.routes {
		if route.matches(routedRequest) {
			handler := route.handler

			if len(route.middlewares) > 0 {
				slog.Info("request routing middlewares started", "request", requestLogValue)
				middlewareStartTime := time.Now()

				for i := len(route.middlewares) - 1; i >= 0; i-- {
					handler = route.middlewares[i](handler)
				}

				slog.Info("request routing middlewares done", "request", requestLogValue, "took", time.Since(middlewareStartTime))
			}

			slog.Info("request routing handler started", "request", requestLogValue)
			handlerStartTime := time.Now()
			handler(w, routedRequest)
			slog.Info("request routing handler done", "request", requestLogValue, "took", time.Since(handlerStartTime))

			return
		}
	}
	slog.Warn("request routing not found", "request", requestLogValue)
	http.NotFound(w, routedRequest)
}
