package consumers

import (
	"reflect"
	"testing"

	"github.com/go-openapi/runtime"
)

func TestPKCS10Consumer(t *testing.T) {
	tests := []struct {
		name string
		want runtime.ConsumerFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCS10Consumer(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCS10Consumer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPKCS7Consumer(t *testing.T) {
	tests := []struct {
		name string
		want runtime.ConsumerFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCS7Consumer(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCS7Consumer() = %v, want %v", got, tt.want)
			}
		})
	}
}
