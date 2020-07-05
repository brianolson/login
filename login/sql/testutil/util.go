package testutil

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	ls "bolson.org/~/src/login/login/sql"
)

func Maybefail(err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	log.Printf(format, args...)
	os.Exit(1)
}

func Mtfail(t *testing.T, err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	t.Errorf(format, args...)
}

// checks everything _other_ than Guid
func UserDeepEqual(expected, actual ls.User) error {
	var msg []string
	if len(expected.Social) != len(actual.Social) {
		msg = append(msg, fmt.Sprintf("expected %d social entries but got %d", len(expected.Social), len(actual.Social)))
	} else {
		for _, se := range expected.Social {
			ok := false
			for _, sa := range actual.Social {
				if se.Service == sa.Service && se.Id == sa.Id {
					ok = true
					break
				}
			}
			if !ok {
				msg = append(msg, fmt.Sprintf("expected social(%s,%s) not found", se.Service, se.Id))
			}
		}
	}

	if len(expected.Email) != len(actual.Email) {
		msg = append(msg, fmt.Sprintf("expected %d email entries but got %d", len(expected.Email), len(actual.Email)))
	} else {
		for _, ee := range expected.Email {
			ok := 0
			for _, ea := range actual.Email {
				if ee.Email == ea.Email {
					if ee.Validated != ea.Validated || ee.Added != ea.Added {
						msg = append(msg, fmt.Sprintf("email %s different metadata expected=%#v actual=%#v", ee.Email, ee.EmailMetadata, ea.EmailMetadata))
						ok = -1
						break
					}
					ok = 1
					break
				}
			}
			if ok == 0 {
				msg = append(msg, fmt.Sprintf("expected email(%s) not found", ee.Email))
			}
		}
	}

	if len(msg) > 0 {
		return errors.New(strings.Join(msg, "\n"))
	}
	return nil
}
