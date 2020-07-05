package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	ls "bolson.org/~/src/login/login/sql"
)

// go get github.com/mattn/go-sqlite3

var tdb *sql.DB
var udb ls.UserDB
var tdbLock sync.Mutex

func mtfail(t *testing.T, err error, format string, args ...interface{}) {
	if err == nil {
		return
	}
	t.Errorf(format, args...)
}

func TestMain(m *testing.M) {
	db, err := sql.Open("sqlite3", ":memory:")
	maybefail(err, "error opening test sqlite3 :memory: db, %v", err)

	udb = ls.NewSqlUserDB(db)

	err = udb.Setup()
	maybefail(err, "error creating tables, %v", err)

	tdb = db

	result := m.Run()
	os.Exit(result)
}

func TestBasicUser(t *testing.T) {
	newUser := ls.User{
		Username: "wat",

		Social: []ls.UserSocial{ls.UserSocial{Service: "z", Id: "alice"}},

		Email: []ls.EmailRecord{ls.EmailRecord{Email: "z@z.z", EmailMetadata: ls.EmailMetadata{Validated: true, Added: 31337}}},
	}
	err := newUser.SetPassword("derp")
	mtfail(t, err, "set password, %v", err)
	tdbLock.Lock()
	defer tdbLock.Unlock()
	xu, err := udb.PutNewUser(&newUser)
	mtfail(t, err, "put user, %v", err)
	if xu.Guid == 0 {
		t.Error("xu.Guid zero")
	}
	tu, err := udb.GetUser(xu.Guid)
	mtfail(t, err, "get user %d, %v", xu.Guid, err)
	err = userDeepEqual(newUser, *tu)
	mtfail(t, err, "get user neq, %v", err)
}

// checks everything _other_ than Guid
func userDeepEqual(expected, actual ls.User) error {
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
