package routing

// list of keys in the r.Context()

type CTX_USER_TYPE string
type CTX_REQUEST_ID_TYPE string
type CTX_SESSION_ID_TYPE string

const (
	CTX_USER       CTX_USER_TYPE       = "user"
	CTX_REQUEST_ID CTX_REQUEST_ID_TYPE = "RequestID"
	CTX_SESSION_ID CTX_SESSION_ID_TYPE = "SessionID"
)
