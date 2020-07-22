package producers

import (
	"github.com/pkg/errors"
	"io"
	"net/http/httptest"
	"testing"
)

func TestPKCS7Producer(t *testing.T) {
	tests := []struct {
		name    string
		w       io.Writer
		i       interface{}
		want    string
		wantErr bool
	}{
		{
			name:    "OK",
			w:       httptest.NewRecorder(),
			i:       "HelloWorld",
			want:    "SGVsbG9Xb3JsZA==",
			wantErr: false,
		},
		{
			name:    "BadWriter",
			w:       &BadWriter{},
			i:       "GoodByeWorld",
			wantErr: true,
		}, {
			name:    "BadData",
			w:       httptest.NewRecorder(),
			i:       nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Got is a ProducerFunc
			got := PKCS7Producer()
			if got == nil {
				t.Error("PKCS7Producer() should be a function")
				return
			}

			// Test the ProducerFunc with test data
			if err := got(tt.w, tt.i); err != nil {
				if tt.wantErr == false {
					t.Error(err)
					return
				}
			} else {
				// let's test the content of the writer
				if rw, _ := tt.w.(*httptest.ResponseRecorder); rw != nil {
					if rw.Body.String() != tt.want {
						t.Errorf("Expected: %v, Got: %v", tt.want, rw.Body.String())
						return
					}
				}
			}

		})
	}
}

type BadWriter struct {
}

func (*BadWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("Some Error with write... not really, i'm a mock")
}
