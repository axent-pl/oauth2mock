package routing

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"
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
	dump, _ := httputil.DumpRequest(r, true)
	slog.Info(string(dump))
	for _, route := range h.routes {
		if route.matches(r) {
			slog.Info("Request started", "RemoteAddr", r.RemoteAddr, "Method", r.Method, "Path", r.URL.Path, "Query", r.URL.RawQuery)
			start := time.Now()
			route.handler(w, r)
			took := time.Since(start)
			slog.Info("Request finished", "RemoteAddr", r.RemoteAddr, "Method", r.Method, "Path", r.URL.Path, "Query", r.URL.RawQuery, "tookMS", took)
			return
		}
	}
	slog.Warn("No route for", "RemoteAddr", r.RemoteAddr, "Method", r.Method, "Path", r.URL.Path, "Query", r.URL.RawQuery, "RawPostData", r.Body)
	http.NotFound(w, r)
}
