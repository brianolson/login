package login

import (
	"bolson.org/~/src/login/login/sql"
)

type UserDB = sql.UserDB
type User = sql.User
type UserSocial = sql.UserSocial
type EmailRecord = sql.EmailRecord

var NewEmail = sql.NewEmail

var BadUserError = sql.BadUserError
var NewSqlUserDB = sql.NewSqlUserDB
