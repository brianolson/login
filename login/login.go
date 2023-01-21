package login

import (
	"github.com/brianolson/login/login/crypto"
	"github.com/brianolson/login/login/data"
	"github.com/brianolson/login/login/sql"
)

type UserDB = data.UserDB
type User = data.User
type UserSocial = data.UserSocial
type EmailRecord = data.EmailRecord

var NewEmail = data.NewEmail

var BadUserError = data.BadUserError
var NewSqlUserDB = sql.NewSqlUserDB

var GenerateCookieKey = crypto.GenerateCookieKey
var SetCookieKey = crypto.SetCookieKey
