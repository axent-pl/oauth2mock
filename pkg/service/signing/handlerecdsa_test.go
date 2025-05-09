package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestKeyHandlerECDSA_GetSigningMethod(t *testing.T) {
	type fields struct {
		privateKey *ecdsa.PrivateKey
	}

	privateKey256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	privateKey521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	tests := []struct {
		name   string
		fields fields
		want   SigningMethod
	}{
		{
			name: "ES256",
			fields: fields{
				privateKey: privateKey256,
			},
			want: ES256,
		},
		{
			name: "ES384",
			fields: fields{
				privateKey: privateKey384,
			},
			want: ES384,
		},
		{
			name: "ES521",
			fields: fields{
				privateKey: privateKey521,
			},
			want: ES512,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kh := &ecdsaSigningKey{
				privateKey: tt.fields.privateKey,
			}
			kh.init()
			if got := kh.GetSigningMethod(); got != tt.want {
				t.Errorf("keyHandlerECDSA.GetSigningMethod() = %v, want %v", got, tt.want)
			}
		})
	}
}
