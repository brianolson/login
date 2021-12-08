module github.com/brianolson/login/test_sqlite

go 1.14

require (
	github.com/brianolson/login/login v0.0.0
	github.com/mattn/go-sqlite3 v1.14.9
)

replace github.com/brianolson/login/login => ../login
