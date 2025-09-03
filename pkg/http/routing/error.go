package routing

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/axent-pl/oauth2mock/pkg/errs"
)

func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "request", RequestLogValue(r), "errror", err)
	status := http.StatusInternalServerError
	title := "Internal server error"
	if _, ok := err.(*errs.Err); ok {
		title = err.Error()
	}
	switch {
	case errors.Is(err, errs.ErrInvalidArgument):
		status = http.StatusBadRequest
	case errors.Is(err, errs.ErrNotFound):
		status = http.StatusNotFound
	}
	http.Error(w, title, status)
}
