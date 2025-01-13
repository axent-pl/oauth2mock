package auth

type SubjectHandler interface {
	Name() string
	Credentials() CredentialsHandler
}

type subject struct {
	name        string
	credentials CredentialsHandler
}

func (s *subject) Name() string {
	return s.name
}

func (s *subject) Credentials() CredentialsHandler {
	return s.credentials
}
