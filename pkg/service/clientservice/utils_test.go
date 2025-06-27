package clientservice

import (
	"testing"
)

func TestMatchesWildcard(t *testing.T) {
	type args struct {
		redirectURI       string
		clientRedirectURI string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Test 1 whole placeholder",
			args: args{
				redirectURI:       "http://localhost:8080/products/view?filer=all",
				clientRedirectURI: "*",
			},
			want: true,
		},
		{
			name: "Test 1 placeholder",
			args: args{
				redirectURI:       "http://localhost:8080/products?filer=all",
				clientRedirectURI: "http://localhost:8080/*",
			},
			want: true,
		},
		{
			name: "Test 2 placeholders",
			args: args{
				redirectURI:       "http://localhost:8080/products?filer=all",
				clientRedirectURI: "http://localhost:*/*",
			},
			want: true,
		},
		{
			name: "Test 2 placeholders should not match",
			args: args{
				redirectURI:       "http://localhoster:8080/products?filer=all",
				clientRedirectURI: "http://localhost:*/*",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchesWildcard(tt.args.redirectURI, tt.args.clientRedirectURI); got != tt.want {
				t.Errorf("MatchesWildcard() = %v, want %v", got, tt.want)
			}
		})
	}
}
