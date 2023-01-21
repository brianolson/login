module github.com/brianolson/login/test_postgres

go 1.24.0

toolchain go1.24.6

require (
	github.com/brianolson/login/login v0.0.0
	github.com/lib/pq v1.7.0
)

require (
	github.com/brianolson/cbor_go v1.0.0 // indirect
	golang.org/x/crypto v0.47.0 // indirect
)

replace github.com/brianolson/login/login => ../login
