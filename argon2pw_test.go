package argon2pw

import (
	"strings"
	"testing"
)

func TestGenerateSaltedHash(t *testing.T) {
	tests := []struct {
		name         string
		password     string
		hashSegments int
		hashLength   int
		wantErr      bool
	}{
		{name: "Should Work", password: "Password1", hashSegments: 7, hashLength: 89, wantErr: false},
		{name: "Should Not Work", password: "", hashSegments: 1, hashLength: 0, wantErr: true},
		{name: "Should Work 2", password: "gS</5Tu>3@(<FCtY", hashSegments: 7, hashLength: 89, wantErr: false},
		{name: "Should Work 3", password: `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, hashSegments: 7, hashLength: 89, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateSaltedHash(tt.password)
			hashSegments := strings.Split(got, "$")
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSaltedHash() = %v, want %v", err, tt.wantErr)
				return
			}
			if len(hashSegments) != tt.hashSegments {
				t.Errorf("GenerateSaltedHash() had %d segments. Want %d", len(hashSegments), tt.hashSegments)
			}
			if len(got) != tt.hashLength {
				t.Errorf("GenerateSaltedHash() hash length = %v, want %v", len(got), tt.hashLength)
			}
		})
	}
}

func TestCompareHashWithPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
		wantErr  bool
	}{
		{name: "Should Work 1", hash: `argon2$4$32768$4$32$/WN2BY5NDzVlHYgw3pqahA==$oLGdDy23gAgbQXmphVVPG0Uax+XbfeUfH/TCpQbEHfc=`, password: `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, want: true, wantErr: false},
		{name: "Should Not Work 1", hash: `argon2$4$32768$4$32$/WN2BY5NDzVlHYgw3pqahA==$XLGdDy23gAgbQXmphVVPG0Uax+XbfeUfH/TCpQbEHfc=`, password: `Y&XEA)_m7q@jb@J"<sXrS]HH"zU`, want: false, wantErr: true},
		{name: "Should Not Work 2", hash: ``, password: ``, want: false, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareHashWithPassword(tt.hash, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareHashWithPassword() error = %v, wantErr %v", err, tt.wantErr)
				t.Errorf("hash is %v", got)
				return
			}
			if got != tt.want {
				t.Errorf("CompareHashWithPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
