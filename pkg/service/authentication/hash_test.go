package authentication

import "testing"

func TestCheckPasswordHash(t *testing.T) {
	type args struct {
		password    string
		encodedHash string
	}

	fooPass := "foo"
	barPass := "bar"
	fooHash, _ := HashPassword(fooPass)

	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "valid password",
			args: args{
				password:    fooPass,
				encodedHash: fooHash,
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "invalid password",
			args: args{
				password:    barPass,
				encodedHash: fooHash,
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckPasswordHash(tt.args.password, tt.args.encodedHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CheckPasswordHash() = %v, want %v", got, tt.want)
			}
		})
	}
}
