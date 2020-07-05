package sql

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"
	"time"

	cbor "github.com/brianolson/cbor_go"
)

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
	PutNewUser(nu *User) (*User, error)

	GetUser(guid uint64) (*User, error)
	GetLocalUser(username string) (*User, error)
	GetSocialUser(service, id string) (*User, error)

	// copy misc data out of User struct into preferences
	SetUserPrefs(user *User) error
	SetUserPassword(user *User) error

	// Set local login for a social-login user
	SetLogin(user *User, username, password string) error

	AddEmail(user *User, email string) error
	DelEmail(user *User, email string) error

	Feedback(user *User, now int64, text string) error

	// Release connection
	Close()
}

func strInStrs(they []string, it string) bool {
	for _, xs := range they {
		if xs == it {
			return true
		}
	}
	return false
}

// byte-array in byte-arrays
func baInBas(they [][]byte, it []byte) bool {
	for _, xs := range they {
		if bytes.Equal(xs, it) {
			return true
		}
	}
	return false
}

// Used in GetUser, GetLocalUser, GetSocialUser which MUST have the
// same result out of SELECT.
func readUserFromSelect(rows *sql.Rows) (*User, error) {
	var email *string
	var err error
	var prefs []byte = nil
	u := &User{}
	u.Email = make([]string, 0)
	u.Social = make([]UserSocial, 0)
	any := false
	var socialkey []byte = nil
	var socialdata []byte = nil
	sokeys := make([][]byte, 0) // list of socialkeys found so far

	for rows.Next() {
		any = true
		email = nil
		socialkey = nil
		socialdata = nil
		err = rows.Scan(&u.Username, &u.Password, &prefs, &email, &u.Guid, &socialkey, &socialdata)
		if err != nil {
			break
		}
		if (email != nil) && (len(*email) > 0) && !strInStrs(u.Email, *email) {
			u.Email = append(u.Email, *email)
		}
		if (socialkey != nil) && (len(socialkey) > 0) && !baInBas(sokeys, socialkey) {
			sokeys = append(sokeys, socialkey)
			service, sid := ParseSocialKey(socialkey)
			if sid == "" {
				log.Printf("failed to parse social key: %#v", socialkey)
			} else {
				u.Social = append(u.Social, UserSocial{
					service,
					sid,
					socialdata,
				})
			}
		}
	}
	if !any {
		return nil, BadUserError
	}
	if (prefs != nil) && (len(prefs) > 0) {
		unpackPrefsBlob(u, prefs)
	}
	return u, err
}

var postgresCreateTables []string

func init() {
	postgresCreateTables = []string{
		`CREATE TABLE IF NOT EXISTS guser (
id bigserial PRIMARY KEY,
username varchar(100), -- may be NULL
password varchar(100), -- may be NULL
prefs bytea -- cbor encoded UserSqlPrefs{}
);
CREATE UNIQUE INDEX IF NOT EXISTS guser_name ON guser ( username )`,
		`CREATE TABLE IF NOT EXISTS user_social (
id bigint, -- foreign key guser.id
socialkey bytea, -- service\0id
socialdata bytea, -- cbor, unpack into specific struct per service in app
PRIMARY KEY (id, socialkey)
);
CREATE UNIQUE INDEX IF NOT EXISTS social_key ON user_social ( socialkey )`,
		`CREATE TABLE IF NOT EXISTS user_email (
id bigint, -- foreign key guser.id
email varchar(100),
data bytea, -- cbor {'valid':bool, ...}
PRIMARY KEY (id, email)
);
CREATE INDEX IF NOT EXISTS user_email_email ON user_email ( email )`,
	}
}

func CreateTables(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, cmd := range postgresCreateTables {
		_, err := tx.Exec(cmd)
		if err != nil {
			log.Printf("sql setup failed: %v", cmd)
			se := tx.Rollback()
			if se != nil {
				log.Printf("tx rollback failed too: %s", se)
			}
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		log.Printf("sql setup transaction failed: %s", err)
		return err
	}
	return nil
}

func GetUser(db *sql.DB, guid uint64) (*User, error) {
	// TODO: user records are probably highly cacheable, and frequently read
	cmd := `SELECT g.username, g.password, g.prefs, e.email, g.id, s.socialkey, s.socialdata FROM guser g LEFT JOIN user_email e ON g.id = e.id LEFT JOIN user_social s ON g.id = s.id WHERE g.id = $1`
	rows, err := db.Query(cmd, guid)
	if err != nil {
		log.Printf("sql err on %#v: %s", cmd, err)
		return nil, err
	}
	return readUserFromSelect(rows)
}

func GetLocalUser(db *sql.DB, uid string) (*User, error) {
	cmd := `SELECT g.username, g.password, g.prefs, e.email, g.id, s.socialkey, s.socialdata FROM guser g LEFT JOIN user_email e ON g.id = e.id LEFT JOIN user_social s ON g.id = s.id WHERE g.username = $1`
	rows, err := db.Query(cmd, uid)
	if err != nil {
		log.Printf("sql err on %#v: %s", cmd, err)
		return nil, err
	}
	return readUserFromSelect(rows)
}

func GetSocialUser(db *sql.DB, service, id string) (*User, error) {
	socialkey := SocialKey(service, id)
	cmd := `SELECT g.username, g.password, g.prefs, e.email, g.id, s.socialkey, s.socialdata FROM user_social s LEFT JOIN guser g ON s.id = g.id LEFT JOIN user_email e ON g.id = e.id WHERE s.socialkey = $1`
	rows, err := db.Query(cmd, socialkey)
	if err != nil {
		log.Printf("sql err on %#v: %s", cmd, err)
		return nil, err
	}
	return readUserFromSelect(rows)
}

func SocialKey(service, uid string) string {
	return service + "\x00" + uid
}

func ParseSocialKey(socialkey []byte) (service, id string) {
	spos := bytes.IndexByte(socialkey, 0)
	if spos < 0 {
		return "", ""
	}
	return string(socialkey[0:spos]), string(socialkey[spos+1:])
}

// CBOR encoded contents of guser table column (prefs bytea)
type UserSqlPrefs struct {
	// Enabled forms
	Enabled []string

	DisplayName *string

	NextParam uint32

	// Sorted list of features special enabled for this user.
	Features []int
}

func prefsBlob(user *User) ([]byte, error) {
	return cbor.Dumps(UserSqlPrefs{user.Enabled, user.DisplayName, user.NextParam, user.Features})
}

func unpackPrefsBlob(user *User, blob []byte) error {
	var uprefs UserSqlPrefs
	var err error
	err = cbor.Loads(blob, &uprefs)
	if err == nil {
		user.Enabled = uprefs.Enabled
		user.DisplayName = uprefs.DisplayName
		user.NextParam = uprefs.NextParam
		user.Features = uprefs.Features
	} else {
		log.Print("bad prefs cbor", err)
	}
	return err
}

func PutNewUser(db *sql.DB, nu *User) (*User, error) {
	if nu.Username != nil {
		ou, _ := GetLocalUser(db, *nu.Username)
		if ou != nil {
			return nil, fmt.Errorf("username \"%s\" already taken", *nu.Username)
		}
		// no collision, moving on
	}
	if (nu.Social != nil) && (len(nu.Social) > 0) {
		for _, si := range nu.Social {
			ou, _ := GetSocialUser(db, si.Service, si.Id)
			if ou != nil {
				// database race? Should have just tried
				// to log in, but maybe found it not
				// in the database, but then it was
				// created elsewhere, and now we're
				// trying to create it here? Probably
				// a page reload will fix everything.
				return nil, fmt.Errorf("social login \"%s %s\" already taken", si.Service, si.Id)
			}
		}
	}
	if (nu.Email != nil) && (len(nu.Email) > 0) {
		for _, em := range nu.Email {
			emrows, err := db.Query(`SELECT id, data FROM user_email WHERE email = $1`, em)
			if err != nil {
				log.Printf("error getting emails in newuser: %s", err)
				return nil, err
			}
			if emrows.Next() {
				// TODO: check that other email is validated
				return nil, fmt.Errorf("email %#v already taken when making new user", em)
			}
		}
	}

	pblob, err := prefsBlob(nu)
	if err != nil {
		log.Print("nu prefs cbor fail", err)
		return nil, err
	}
	tx, err := db.Begin()
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	idrows, err := tx.Query(`INSERT INTO guser (username, password, prefs) VALUES ($1, $2, $3) RETURNING id`, nu.Username, nu.Password, pblob)
	if err != nil {
		log.Printf("error inserting new user: %s", err)
		tx.Rollback()
		return nil, err
	}
	var newGuid uint64 = 0
	if idrows.Next() {
		err = idrows.Scan(&newGuid)
		if err != nil {
			log.Printf("could not get new guid: %s", err)
			tx.Rollback()
			return nil, err
		}
		nu.Guid = newGuid
	}
	// This call to Next which doesn't do anything but return
	// false is necssary due to lib/pq driver oddities!
	for idrows.Next() {
		log.Print("bogus extra rows of return from INSERT!")
	}

	if (nu.Social != nil) && (len(nu.Social) > 0) {
		cmd := `INSERT INTO user_social (id, socialkey, socialdata) VALUES ($1, $2, $3)`

		for _, si := range nu.Social {
			skey := SocialKey(si.Service, si.Id)
			_, err = tx.Exec(cmd, nu.Guid, skey, nil)
			if err != nil {
				log.Printf("error putting user social: %s", err)
				tx.Rollback()
				return nil, err
			}
		}
	}
	if (nu.Email != nil) && (len(nu.Email) > 0) {
		cmd := `INSERT INTO user_email (id, email) VALUES ($1, $2)`
		stmt, err := tx.Prepare(cmd)
		if err != nil {
			log.Printf("error preparing user_email statement %#v: %s", cmd, err)
			tx.Rollback()
			return nil, err
		}

		for _, em := range nu.Email {
			_, err = stmt.Exec(nu.Guid, em)
			if err != nil {
				log.Printf("error putting user email: %s", err)
				tx.Rollback()
				return nil, err
			}
		}
	}

	err = tx.Commit()
	if err != nil {
		log.Printf("err on new user commit: %s %T %#v", err, err, err)
		return nil, err
	}

	return nu, nil
}

func SetUserPrefs(db *sql.DB, user *User) error {
	pblob, err := prefsBlob(user)
	if err != nil {
		log.Print("set prefs cbor fail", err)
		return err
	}
	_, err = db.Exec(`UPDATE guser SET prefs = $1 WHERE id = $2`, pblob, user.Guid)
	return err
}

func SetUserPassword(db *sql.DB, user *User) error {
	_, err := db.Exec(`UPDATE guser SET password = $1 WHERE id = $2`, user.Password, user.Guid)
	return err
}

// Set local login for a social-login user
func SetLogin(db *sql.DB, user *User, username, password string) error {
	_, err := db.Exec(`UPDATE guser SET username = $1, password = $2 WHERE id = $3`, username, password, user.Guid)
	return err
}

func AddEmail(db *sql.DB, user *User, email string) error {
	metablob, err := cbor.Dumps(EmailMetadata{false, time.Now().Unix()})
	if err != nil {
		log.Print("failed to encode email metadata cbor ", err)
		metablob = make([]byte, 0)
	}
	_, err = db.Exec(`INSERT INTO user_email (id, email, data) VALUES ($1, $2, $3)`, user.Guid, email, metablob)
	return err
}

func DelEmail(db *sql.DB, user *User, email string) error {
	_, err := db.Exec(`DELETE FROM user_email WHERE id = $1 AND email = $2`, user.Guid, email)
	return err
}

func Feedback(db *sql.DB, user *User, now int64, text string) error {
	_, err := db.Exec(`INSERT INTO feedback (guid, millis, msg) VALUES ($1, $2, $3)`, user.Guid, now, text)
	return err
}

type SqlUserDB struct {
	db *sql.DB
}

func NewSqlUserDB(db *sql.DB) *SqlUserDB {
	return &SqlUserDB{db}
}

func (sdb *SqlUserDB) PutNewUser(nu *User) (*User, error) {
	return PutNewUser(sdb.db, nu)
}

func (sdb *SqlUserDB) GetUser(guid uint64) (*User, error) {
	return GetUser(sdb.db, guid)
}
func (sdb *SqlUserDB) GetLocalUser(uid string) (*User, error) {
	return GetLocalUser(sdb.db, uid)
}
func (sdb *SqlUserDB) GetSocialUser(service, id string) (*User, error) {
	return GetSocialUser(sdb.db, service, id)
}

func (sdb *SqlUserDB) SetUserPrefs(xuser *User) error {
	return SetUserPrefs(sdb.db, xuser)
}
func (sdb *SqlUserDB) SetUserPassword(xuser *User) error {
	return SetUserPassword(sdb.db, xuser)
}

// Set local login for a social-login user
func (sdb *SqlUserDB) SetLogin(user *User, username, password string) error {
	return SetLogin(sdb.db, user, username, password)
}

func (sdb *SqlUserDB) AddEmail(user *User, email string) error {
	return AddEmail(sdb.db, user, email)
}

func (sdb *SqlUserDB) DelEmail(user *User, email string) error {
	return DelEmail(sdb.db, user, email)
}

func (sdb *SqlUserDB) Feedback(user *User, now int64, text string) error {
	return Feedback(sdb.db, user, now, text)
}

func (sdb *SqlUserDB) CreateTables() error {
	return CreateTables(sdb.db)
}

func (sdb *SqlUserDB) Close() {
	sdb.db.Close()
	sdb.db = nil
}
