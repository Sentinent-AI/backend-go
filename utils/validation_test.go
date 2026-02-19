package utils

import "testing"

func TestIsEmailValid(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{"test@example.com", true},
		{"TEST@example.com", true},      // Current one might fail this
		{"test@example.museum", true},   // Current one might fail this (TLD length > 4)
		{"test@sub.example.com", true},
		{"invalid-email", false},
		{"@example.com", false},
		{"test@", false},
		{"test@example", false},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			if got := IsEmailValid(tt.email); got != tt.expected {
				t.Errorf("IsEmailValid(%q) = %v; want %v", tt.email, got, tt.expected)
			}
		})
	}
}
