package data

// UserDB interface to be implemented by sql, kvstore, etc
//
// Actions on users:
// new user (with local/social/email)
// disable user
// delete user
//
// add local login to user
// update user local password
// update user prefs
//
// add/del email to user
// set metadata for email
//
// add/del social login to user
// set metadata for social
type UserDB interface {
	// Setup will create or mirgate tables
	Setup() error

	// PutNewUser takes a User that is being assembled, has some user/pass or social-id, assigns new guid and returs updated User struct.
	// ensure that local username and social id aren't taken
	// put user (and social, and local password)
	PutNewUser(nu *User) (*User, error)

	GetUser(guid int64) (*User, error)
	GetLocalUser(username string) (*User, error)
	GetSocialUser(service, id string) (*User, error)

	// copy misc data out of User struct into preferences
	SetUserPrefs(user *User) error
	SetUserPassword(user *User) error

	// Set local login for a social-login user
	SetLogin(user *User, username, password string) error

	AddEmail(user *User, email EmailRecord) error
	DelEmail(user *User, email string) error

	Feedback(user *User, now int64, text string) error
}
