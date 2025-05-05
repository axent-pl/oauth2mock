package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestKeyHandlerRSA_GetSigningMethod(t *testing.T) {
	type fields struct {
		privateKey *rsa.PrivateKey
	}

	privateKey256, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKey384, _ := rsa.GenerateKey(rand.Reader, 3072)
	privateKey512, _ := rsa.GenerateKey(rand.Reader, 4096)

	tests := []struct {
		name   string
		fields fields
		want   SigningMethod
	}{
		{
			name: "RS256",
			fields: fields{
				privateKey: privateKey256,
			},
			want: RS256,
		},
		{
			name: "RS384",
			fields: fields{
				privateKey: privateKey384,
			},
			want: RS384,
		},
		{
			name: "RS512",
			fields: fields{
				privateKey: privateKey512,
			},
			want: RS512,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kh := &rsaSigningKey{
				privateKey: tt.fields.privateKey,
			}
			kh.init()
			if got := kh.GetSigningMethod(); got != tt.want {
				t.Errorf("keyHandlerRSA.GetSigningMethod() = %v, want %v", got, tt.want)
			}
		})
	}
}
