package auth

import "log/slog"

// ErrorHandler acts as the terminal handler for errors.
type ErrorHandler interface {
	Handle(err error)
}

// LogErrorHandler logs an error using [slog.Logger].
type LogErrorHandler struct {
	Logger *slog.Logger
}

func (h LogErrorHandler) Handle(err error) {
	if h.Logger == nil {
		return
	}

	h.Logger.Error(err.Error(), slog.Any("error", err))
}
