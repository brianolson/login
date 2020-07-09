package login

import (
	"github.com/brianolson/login/login/crypto"
	"github.com/brianolson/login/login/sql"
)

type UserDB = sql.UserDB
type User = sql.User
type UserSocial = sql.UserSocial
type EmailRecord = sql.EmailRecord

var NewEmail = sql.NewEmail

var BadUserError = sql.BadUserError
var NewSqlUserDB = sql.NewSqlUserDB

var GenerateCookieKey = crypto.GenerateCookieKey
var SetCookieKey = crypto.SetCookieKey
