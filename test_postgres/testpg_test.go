package main

import (
	"database/sql"
	"flag"
	"os"
	"sync"
	"testing"

	_ "github.com/lib/pq"

	ls "bolson.org/~/src/login/login/sql"
	tu "bolson.org/~/src/login/login/sql/testutil"
)

// go get github.com/lib/pq

var tdb *sql.DB
var udb ls.UserDB
var tdbLock sync.Mutex

var mtfail = tu.Mtfail
var userDeepEqual = tu.UserDeepEqual

func TestMain(m *testing.M) {
	var pgConnectString string
	flag.StringVar(&pgConnectString, "postgres", "", "connection string for postgres")
	flag.Parse()
	db, err := sql.Open("postgres", pgConnectString)
	maybefail(err, "error opening postgres db, %v", err)

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

		Social: []ls.UserSocial{
			ls.UserSocial{Service: "z", Id: "alice"},
			ls.UserSocial{Service: "y", Id: "artemis"},
		},

		Email: []ls.EmailRecord{
			ls.EmailRecord{Email: "z@z.z", EmailMetadata: ls.EmailMetadata{Validated: true, Added: 31337}},
			ls.EmailRecord{Email: "y@y.y", EmailMetadata: ls.EmailMetadata{Validated: false, Added: 12345}},
		},
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
	mtfail(t, err, "get user guid neq, %v", err)

	tu, err = udb.GetLocalUser("wat")
	mtfail(t, err, "get user name=%s, %v", "wat", err)
	err = userDeepEqual(newUser, *tu)
	mtfail(t, err, "get user wat neq, %v", err)

	tu, err = udb.GetSocialUser("z", "alice")
	mtfail(t, err, "get user z:alice, %v", err)
	err = userDeepEqual(newUser, *tu)
	mtfail(t, err, "get user z:alice neq, %v", err)
}
