module github.com/brianolson/login/test_postgres

go 1.16

require (
	github.com/brianolson/login/login v0.0.0
	github.com/lib/pq v1.7.0
)

replace github.com/brianolson/login/login => ../login
