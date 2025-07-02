package consentservice

type defaultConsentHandler struct {
	scope   string
	granted bool
	revoked bool
}

func NewConsentHandler(scope string) (ConsentHandler, error) {
	h := &defaultConsentHandler{
		scope:   scope,
		granted: false,
		revoked: false,
	}
	return h, nil
}

func (h *defaultConsentHandler) GetScope() string {
	return h.scope
}
func (h *defaultConsentHandler) IsGranted() bool {
	return h.granted
}
func (h *defaultConsentHandler) IsRevoked() bool {
	return h.revoked
}
func (h *defaultConsentHandler) Grant() error {
	h.granted = true
	h.revoked = false
	return nil
}
func (h *defaultConsentHandler) Revoke() error {
	h.granted = false
	h.revoked = true
	return nil
}
