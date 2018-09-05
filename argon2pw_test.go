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
		{name: "Should Work", password: "Password1", hashSegments: 7, hashLength: 111, wantErr: false},
		{name: "Should Not Work", password: "", hashSegments: 1, hashLength: 0, wantErr: true},
		{name: "Should Work 2", password: "gS</5Tu>3@(<FCtY", hashSegments: 7, hashLength: 111, wantErr: false},
		{name: "Should Work 3", password: `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, hashSegments: 7, hashLength: 111, wantErr: false},
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
		isValid  bool
		wantErr  bool
	}{
		{name: "Should Work 1", hash: `argon2id$1$65536$4$32$Kmmw5Rb2JicAHlGL+yIvE5AlamkCZimr9vEqqgxj4pU=$BJzVSk9azcO/6Po+x6qWwFUFZlBy9sUsp4eSDzv20sU=`, password: `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, isValid: true, wantErr: false},
		{name: "Should Not Work 1", hash: `argon2id$1$65536$4$32$IJwacnund802ogLkPaNTHuspQBrAwKlySItlOcKvpaI=$eGVF7y4cyufIVajJFYf/yoRQp8BJS+Qplx5bYXSXX2A=`, password: `Y&XEA)_m7q@jb@J"<sXrS]HH"zU`, isValid: false, wantErr: true},
		{name: "Should Not Work 2", hash: ``, password: ``, isValid: false, wantErr: true},
		{name: "Should Not Work 3", hash: `badHash`, password: ``, isValid: false, wantErr: true},
		{name: "Should Work 2", hash: `argon2$4$32768$4$32$/WN2BY5NDzVlHYgw3pqahA==$oLGdDy23gAgbQXmphVVPG0Uax+XbfeUfH/TCpQbEHfc=`, password: `Y&jEA)_m7q@jb@J"<sXrS]HH"zU`, isValid: true, wantErr: false},
		{name: "Should Not Work 4", hash: `argon2$4$32768$4$32$/WN2BY5NDzVlHYgw3pqahA==$XLGdDy23gAgbQXmphVVPG0Uax+XbfeUfH/TCpQbEHfc=`, password: `Y&XEA)_m7q@jb@J"<sXrS]HH"zU`, isValid: false, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareHashWithPassword(tt.hash, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompareHashWithPassword() error = %v, wantErr %v", err, tt.wantErr)
				t.Errorf("hash is %v", got)
				return
			}
			if got != tt.isValid {
				t.Errorf("CompareHashWithPassword() = %v, want %v", got, tt.isValid)
			}
		})
	}
}
