package errs

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

var (
	ErrInvalidArgument  = errors.New("invalid argument")
	ErrNotFound         = errors.New("resource not found")
	ErrAlreadyExists    = errors.New("resource already exists")
	ErrUnauthenticated  = errors.New("unauthenticated")
	ErrPermissionDenied = errors.New("permission denied")
	ErrInternal         = errors.New("internal error")
)

type Option func(*Err)

type Err struct {
	text    string
	details string
	kind    error
	causes  []error
	caller  string
}

func New(msg string, kind error, details ...string) *Err {
	e := &Err{text: msg, kind: kind, causes: make([]error, 0)}
	if len(details) > 0 {
		e.details = details[0]
	}
	pc, _, _, ok := runtime.Caller(1)
	caller := runtime.FuncForPC(pc)
	if ok && caller != nil {
		e.caller = caller.Name()[5:]
	}
	return e
}

func Wrap(public string, causes ...error) *Err {
	e := &Err{text: public, details: "", causes: causes}
	pc, _, _, ok := runtime.Caller(1)
	caller := runtime.FuncForPC(pc)
	if ok && caller != nil {
		e.caller = caller.Name()[5:]
	}
	return e
}

func (e *Err) Unwrap() []error {
	var next []error
	if e.kind != nil {
		next = append(next, e.kind)
	}
	if len(e.causes) > 0 {
		next = append(next, e.causes...)
	}
	if len(next) == 0 {
		return nil
	}
	return next
}

func (e *Err) Is(target error) bool {
	return errors.Is(e.kind, target)
}

func (e *Err) Error() string {
	return e.text
}

func (e *Err) WithDetails(details string) *Err {
	e.details = details
	return e
}

func (e *Err) WithDetailsf(format string, args ...any) *Err {
	e.details = fmt.Sprintf(format, args...)
	return e
}

func (e *Err) WithKind(err error) *Err {
	e.kind = err
	return e
}

func (e *Err) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			// Verbose, multi-line format
			fmt.Fprintf(s, "error: %s", e.text)
			if e.kind != nil {
				fmt.Fprintf(s, "\nkind:   %s", e.kind)
			}
			if e.details != "" {
				fmt.Fprintf(s, "\ndetails:%s", maybeIndent(e.details))
			}
			if e.caller != "" {
				fmt.Fprintf(s, "\ncaller: %s", e.caller)
			}
			if len(e.causes) > 0 {
				fmt.Fprint(s, "\ncauses:")
				for i, c := range e.causes {
					fmt.Fprintf(s, "\n  %d) %T: %v", i+1, c, c)
				}
			}
			return
		}
		// Default %v: just the public text
		fallthrough
	case 's':
		fmt.Fprint(s, e.Error())
	case 'q':
		fmt.Fprintf(s, "%q", e.Error())
	default:
		fmt.Fprint(s, e.Error())
	}
}

func maybeIndent(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			indented := "\n  " + s[i+1:]
			return " " + s[:i] + strings.ReplaceAll(indented, "\n", "\n  ")
		}
	}
	return " " + s
}
