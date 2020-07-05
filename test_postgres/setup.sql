CREATE USER logintest NOSUPERUSER NOCREATEDB NOCREATEROLE LOGIN PASSWORD 'AAAA';
DROP DATABASE IF EXISTS logintest;
CREATE DATABASE logintest OWNER logintest;

-- dropdb --if-exists logintest && createdb --owner=logintest logintest && go test -postgres "dbname=logintest sslmode=disable user=logintest password=AAAA"
