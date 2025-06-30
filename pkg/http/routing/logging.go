package routing

import (
	"log/slog"
	"net/http"
	"strconv"
)

func RequestLogValue(r *http.Request) slog.Value {
	requestID := ""
	if id, ok := r.Context().Value("RequestID").(string); ok {
		requestID = id
	}

	return slog.GroupValue(
		slog.String("RequestID", requestID),
		slog.String("RemoteAddr", r.RemoteAddr),
		slog.String("Method", r.Method),
		slog.String("Path", r.URL.Path),
		slog.String("Query", r.URL.RawQuery),
		slog.String("Host", r.Host),
		slog.String("UserAgent", r.UserAgent()),
		slog.String("Referer", r.Referer()),
		slog.String("ContentLength", strconv.FormatInt(r.ContentLength, 10)),
		slog.String("Proto", r.Proto),
	)
}
