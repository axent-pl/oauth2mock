package error

import (
	"testing"
)

func TestPkgError_Is(t *testing.T) {
	type fields struct {
		msg  string
		kind error
	}
	type args struct {
		target error
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "ErrMissingCredUsernameOrPassword is ErrInvalidCreds",
			fields: fields{
				msg:  "missing username or password",
				kind: ErrUserCredsInvalid,
			},
			args: args{
				target: ErrUserCredsInvalid,
			},
			want: true,
		},
		{
			name: "ErrMissingCredUsername is ErrInvalidCreds",
			fields: fields{
				msg:  "missing username",
				kind: ErrUserCredsMissingUsernameOrPassword,
			},
			args: args{
				target: ErrUserCredsInvalid,
			},
			want: true,
		},
		{
			name: "custom of ErrMissingCredPassword is ErrInvalidCreds",
			fields: fields{
				msg:  "password is too short",
				kind: ErrUserCredsMissingPassword,
			},
			args: args{
				target: ErrUserCredsInvalid,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &PkgError{
				msg:  tt.fields.msg,
				kind: tt.fields.kind,
			}
			if got := e.Is(tt.args.target); got != tt.want {
				t.Errorf("PkgError.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}
