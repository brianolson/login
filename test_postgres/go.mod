module bolson.org/~/src/login/test_postgres

go 1.14

require (
	bolson.org/~/src/login/login v0.0.0
	github.com/lib/pq v1.7.0
)

replace bolson.org/~/src/login/login => ../login

replace bolson.org/~/src/httpcache => ../../httpcache
