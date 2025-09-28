package brx

import (
	"testing"
)

func TestNewApp(t *testing.T) {
	builder := NewApp()

	if builder == nil {
		t.Fatal("NewApp() returned nil")
	}
}
