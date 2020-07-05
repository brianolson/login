package main

import (
	"database/sql"
	"os"
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
}
