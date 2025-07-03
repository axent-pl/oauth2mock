package consentservice

type defaultConsentHandler struct {
	scope    string
	required bool // true if user consent is required for the scope
	granted  bool
	revoked  bool
}

func NewConsentHandler(scope string) (ConsentHandler, error) {
	h := &defaultConsentHandler{
		scope:    scope,
		required: true,
		granted:  false,
		revoked:  false,
	}
	return h, nil
}

func (h *defaultConsentHandler) GetScope() string {
	return h.scope
}
func (h *defaultConsentHandler) IsRequired() bool {
	return h.required
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
