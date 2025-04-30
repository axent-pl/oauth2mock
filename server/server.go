package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/axent-pl/oauth2mock/routing"
)

type Serverer interface {
	Start(ctx context.Context) error
}

type server struct {
	Addr   string
	Router routing.Router
}

func NewServer(address string, router routing.Router) (Serverer, error) {
	s := &server{
		Addr:   address,
		Router: router,
	}
	return s, nil
}

func (s *server) Start(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:    s.Addr,
		Handler: &s.Router,
	}

	done := make(chan error)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			done <- err
		}
		done <- nil
	}()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Server stopped by context")
			return httpServer.Shutdown(context.Background())
		case err := <-done:
			slog.Error("Server crashed", "error", err)
			return err
		}
	}
}
