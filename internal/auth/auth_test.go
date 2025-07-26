package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("valid header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey validapikey123")

		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if apiKey != "validapikey123" {
			t.Errorf("expected 'validapikey123', got '%s'", apiKey)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		headers := http.Header{}

		_, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("malformed header: wrong scheme", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer sometoken")

		_, err := GetAPIKey(headers)
		if err == nil || err.Error() != "malformed authorization header" {
			t.Errorf("expected malformed header error, got %v", err)
		}
	})

	t.Run("malformed header: missing token", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		_, err := GetAPIKey(headers)
		if err == nil || err.Error() != "malformed authorization header" {
			t.Errorf("expected malformed header error, got %v", err)
		}
	})
}
