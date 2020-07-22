package producers

import (
	"encoding/base64"
	"fmt"
	"github.com/go-openapi/runtime"
	"io"
	"reflect"
)

//PKCS7Producer parses and generates PKCS7 structures
func PKCS7Producer() runtime.ProducerFunc {
	return func(writer io.Writer, i interface{}) (err error) {

		// Attempt to cast i to a string
		if s, ok := i.(string); !ok {
			// i is not string. make error
			fmt.Printf("not string type: %v", reflect.TypeOf(i))
		} else {
			// With string convert it to base64 encoded
			encodedString := base64.StdEncoding.EncodeToString([]byte(s))
			if _, err = writer.Write([]byte(encodedString)); err != nil {
				return err
			}
		}
		return err
	}
}
