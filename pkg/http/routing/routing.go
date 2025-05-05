package routing

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/google/uuid"
)

type route struct {
	method        string
	path          string
	postFormValue map[string]string
	queryValue    map[string]string
	handler       func(w http.ResponseWriter, r *http.Request)
}

type HandlerFunc func(w http.ResponseWriter, r *http.Request)

type Router struct {
	routes []*route
}

type RouteOption func(*route) error

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

func (h *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, "RequestID", uuid.New().String())
	routedRequest := r.WithContext(ctx)

	dump, _ := httputil.DumpRequest(routedRequest, true)
	slog.Debug(string(dump))

	slog.Info("Routing routing", "RequestID", routedRequest.Context().Value("RequestID"), "RemoteAddr", routedRequest.RemoteAddr, "Method", routedRequest.Method, "Path", routedRequest.URL.Path, "Query", routedRequest.URL.RawQuery)
	for _, route := range h.routes {
		if route.matches(routedRequest) {
			slog.Info("Routing routing done", "RequestID", routedRequest.Context().Value("RequestID"))

			slog.Info("Routing calling handler", "RequestID", routedRequest.Context().Value("RequestID"))
			start := time.Now()
			route.handler(w, routedRequest)
			took := time.Since(start)
			slog.Info("Routing calling handler done", "RequestID", routedRequest.Context().Value("RequestID"), "tookMS", took)

			return
		}
	}
	slog.Warn("Routing routing failed", "RequestID", routedRequest.Context().Value("RequestID"))

	http.NotFound(w, r)
}
