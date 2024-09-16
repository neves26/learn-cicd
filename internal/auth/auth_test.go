package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeySuccess(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-api-key")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedAPIKey := "my-secret-api-key"
	if apiKey != expectedAPIKey {
		t.Errorf("expected API key %v, got %v", expectedAPIKey, apiKey)
	}
}

func TestGetAPIKeyNoAuthHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected error, got none")
	}

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKeyMalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-secret-api-key")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected error, got none")
	}

	expectedErr := "malformed authorization header"
	if err.Error() != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

