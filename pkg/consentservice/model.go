package consentservice

type defaultConsent struct {
	scope    string
	required bool // true if user consent is required for the scope
	granted  bool
	revoked  bool
}

type NewConsentOption func(*defaultConsent) error

func NewConsent(scope string, options ...NewConsentOption) (Consenter, error) {
	h := &defaultConsent{
		scope:    scope,
		required: true,
		granted:  false,
		revoked:  false,
	}
	return h, nil
}

func WithRequired(required bool) NewConsentOption {
	return func(c *defaultConsent) error {
		c.required = required
		return nil
	}
}

func WithGranted(granted bool) NewConsentOption {
	return func(c *defaultConsent) error {
		c.granted = granted
		c.revoked = !granted
		return nil
	}
}

func (h *defaultConsent) GetScope() string {
	return h.scope
}
func (h *defaultConsent) IsRequired() bool {
	return h.required
}
func (h *defaultConsent) IsGranted() bool {
	return h.granted
}
func (h *defaultConsent) IsRevoked() bool {
	return h.revoked
}
func (h *defaultConsent) SetState(state bool) error {
	if state {
		return h.Grant()
	}
	return h.Revoke()
}
func (h *defaultConsent) Grant() error {
	h.granted = true
	h.revoked = false
	return nil
}
func (h *defaultConsent) Revoke() error {
	h.granted = false
	h.revoked = true
	return nil
}
