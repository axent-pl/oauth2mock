package sessionservice

type SessionService interface {
	Get(string) (SessionData, bool)
	Put(string, SessionData)
}
