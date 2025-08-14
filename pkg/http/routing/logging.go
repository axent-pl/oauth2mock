package routing

import (
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

func RequestIDLogValue(r *http.Request) slog.Value {
	requestID := ""
	if id, ok := r.Context().Value(CTX_REQUEST_ID).(string); ok {
		requestID = id
	}
	return slog.GroupValue(slog.String("RequestID", requestID))
}

func RequestLogValue(r *http.Request) slog.Value {
	requestID := ""
	if id, ok := r.Context().Value(CTX_REQUEST_ID).(string); ok {
		requestID = id
	}

	authHeader := r.Header.Get("Authorization")
	authType := ""
	if authHeader != "" {
		if parts := strings.SplitN(authHeader, " ", 2); len(parts) == 2 {
			authType = strings.ToLower(parts[0])
		}
	}

	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = contentType // fallback to original if parsing fails
	}

	queryMap := make(map[string]string)
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			queryMap[k] = v[0]
		} else {
			queryMap[k] = ""
		}
	}

	return slog.GroupValue(
		slog.String("RequestID", requestID),
		slog.String("RemoteAddr", r.RemoteAddr),
		slog.String("Method", r.Method),
		slog.String("Path", r.URL.Path),
		slog.Any("Query", queryMap),
		slog.String("Host", r.Host),
		slog.String("UserAgent", r.UserAgent()),
		slog.String("Referer", r.Referer()),
		slog.String("ContentLength", strconv.FormatInt(r.ContentLength, 10)),
		slog.String("Proto", r.Proto),
		slog.Group("Headers",
			slog.String("AuthorizationType", authType),
			slog.String("X-Forwarded-For", r.Header.Get("X-Forwarded-For")),
			slog.String("X-Request-ID", r.Header.Get("X-Request-ID")),
			slog.String("Accept", r.Header.Get("Accept")),
			slog.String("Content-Type", mediaType),
		),
	)
}
