package sql

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"
	"reflect"

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
	// Setup will create or mirgate tables
	Setup() error

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
// Processes SELECT username, password, password, prefs, email, emailmeta, id, socialkey, socialdata
// LEFT JOIN of email and social tables may cause repetition!
func readUserFromSelect(rows *sql.Rows) (*User, error) {
	var email []byte
	var emailmetablob []byte
	var err error
	var prefs []byte = nil
	u := &User{}
	u.Email = make([]EmailRecord, 0)
	u.Social = make([]UserSocial, 0)
	any := false
	var socialkey []byte = nil
	var socialdata []byte = nil
	sokeys := make([][]byte, 0) // list of socialkeys found so far

	for rows.Next() {
		any = true
		email = nil
		emailmetablob = nil
		socialkey = nil
		socialdata = nil
		err = rows.Scan(&u.Username, &u.Password, &prefs, &email, &emailmetablob, &u.Guid, &socialkey, &socialdata)
		if err != nil {
			break
		}
		if (email != nil) && (len(email) > 0) && !u.HasEmail(string(email)) {
			ne := EmailRecord{Email: string(email)}
			if len(emailmetablob) > 0 {
				cbor.Loads(emailmetablob, &ne.EmailMetadata)
			}
			u.Email = append(u.Email, ne)
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

// sql commands for postgres.
// postgres is the baseline, others (sqlite3) deviate from it
const (
	createGuser = `CREATE TABLE IF NOT EXISTS guser (
id bigserial PRIMARY KEY,
username varchar(100), -- may be NULL
password varchar(100), -- may be NULL
prefs bytea -- cbor encoded UserSqlPrefs{}
)`
	createGuserNameIndex = `CREATE UNIQUE INDEX IF NOT EXISTS guser_name ON guser ( username )`

	createUserSocial = `CREATE TABLE IF NOT EXISTS user_social (
id bigint, -- foreign key guser.id
socialkey bytea, -- service\0id
socialdata bytea, -- cbor, unpack into specific struct per service in app
PRIMARY KEY (id, socialkey)
)`
	createUserSocialKeyIndex = `CREATE UNIQUE INDEX IF NOT EXISTS social_key ON user_social ( socialkey )`

	createUserEmail = `CREATE TABLE IF NOT EXISTS user_email (
id bigint, -- foreign key guser.id
email varchar(100),
data bytea, -- cbor {'valid':bool, ...}
PRIMARY KEY (id, email)
)`
	creaetUserEmailIndex = `CREATE INDEX IF NOT EXISTS user_email_email ON user_email ( email )`
)

func dbTxCmdList(db *sql.DB, cmds []string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // nop if committed
	for _, cmd := range cmds {
		_, err := tx.Exec(cmd)
		if err != nil {
			return fmt.Errorf("sql failed %#v, %v", cmd, err)
		}
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit of %d commands failed, %v", len(cmds), err)
	}
	return nil
}

func postgresCreateTables(db *sql.DB) error {
	cmds := []string{
		createGuser,
		createGuserNameIndex,
		createUserSocial,
		createUserSocialKeyIndex,
		createUserEmail,
		creaetUserEmailIndex,
	}
	return dbTxCmdList(db, cmds)
}

func postgresGetUser(db *sql.DB, guid int64) (*User, error) {
	// TODO: user records are probably highly cacheable, and frequently read
	cmd := `SELECT g.username, g.password, g.prefs, e.email, e.data, g.id, s.socialkey, s.socialdata FROM guser g LEFT JOIN user_email e ON g.id = e.id LEFT JOIN user_social s ON g.id = s.id WHERE g.id = $1`
	rows, err := db.Query(cmd, guid)
	if err != nil {
		log.Printf("sql err on %#v: %s", cmd, err)
		return nil, err
	}
	return readUserFromSelect(rows)
}

func postgresGetLocalUser(db *sql.DB, uid string) (*User, error) {
	cmd := `SELECT g.username, g.password, g.prefs, e.email, e.data, g.id, s.socialkey, s.socialdata FROM guser g LEFT JOIN user_email e ON g.id = e.id LEFT JOIN user_social s ON g.id = s.id WHERE g.username = $1`
	rows, err := db.Query(cmd, uid)
	if err != nil {
		log.Printf("sql err on %#v: %s", cmd, err)
		return nil, err
	}
	return readUserFromSelect(rows)
}

func postgresGetSocialUser(db *sql.DB, service, id string) (*User, error) {
	socialkey := SocialKey(service, id)
	cmd := `SELECT g.username, g.password, g.prefs, e.email, e.data, g.id, s.socialkey, s.socialdata FROM user_social s LEFT JOIN guser g ON s.id = g.id LEFT JOIN user_email e ON g.id = e.id WHERE s.socialkey = $1`
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

/*
// CBOR encoded contents of guser table column (prefs bytea)
type UserSqlPrefs struct {
	// Enabled forms
	Enabled []string

	DisplayName *string

	NextParam uint32

	// Sorted list of features special enabled for this user.
	Features []int
}
*/

type PrefsBlob struct {
	DisplayName string                 `json:"dn,omitempty"`
	Data        map[string]interface{} `json:"d,omitempty"`
}

func prefsBlob(user *User) ([]byte, error) {
	return cbor.Dumps(PrefsBlob{user.DisplayName, user.Data})
}

func unpackPrefsBlob(user *User, blob []byte) error {
	var uprefs PrefsBlob
	var err error
	err = cbor.Loads(blob, &uprefs)
	if err == nil {
		user.DisplayName = uprefs.DisplayName
		user.Data = uprefs.Data
	} else {
		log.Print("bad prefs cbor", err)
	}
	return err
}

func commonPutNewUser(xd innerDriver, nu *User) (*User, error) {
	db := xd.DB()
	if len(nu.Username) > 0 {
		ou, _ := xd.GetLocalUser(nu.Username)
		if ou != nil {
			return nil, fmt.Errorf("username \"%s\" already taken", nu.Username)
		}
		// no collision, moving on
	}
	if (nu.Social != nil) && (len(nu.Social) > 0) {
		for _, si := range nu.Social {
			ou, _ := xd.GetSocialUser(si.Service, si.Id)
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
			emrows, err := db.Query(`SELECT id, data FROM user_email WHERE email = $1`, em.Email)
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
		return nil, err
	}
	defer tx.Rollback() // nop if committed
	newGuid, err := xd.PutGuser(tx, nu, pblob)
	if err != nil {
		return nil, err
	}
	nu.Guid = newGuid

	if (nu.Social != nil) && (len(nu.Social) > 0) {
		cmd := `INSERT INTO user_social (id, socialkey, socialdata) VALUES ($1, $2, $3)`

		for _, si := range nu.Social {
			skey := SocialKey(si.Service, si.Id)
			_, err = tx.Exec(cmd, nu.Guid, skey, nil)
			if err != nil {
				log.Printf("error putting user social: %s", err)
				return nil, err
			}
		}
	}
	if (nu.Email != nil) && (len(nu.Email) > 0) {
		cmd := `INSERT INTO user_email (id, email, data) VALUES ($1, $2, $3)`
		stmt, err := tx.Prepare(cmd)
		if err != nil {
			log.Printf("error preparing user_email statement %#v: %s", cmd, err)
			tx.Rollback()
			return nil, err
		}

		for _, em := range nu.Email {
			edblob, err := cbor.Dumps(em.EmailMetadata)
			if err != nil {
				err = fmt.Errorf("could not cbor encode email metadata for %s, %v", em.Email, err)
				return nil, err
			}
			_, err = stmt.Exec(nu.Guid, em.Email, edblob)
			if err != nil {
				err = fmt.Errorf("error putting user email: %s", err)
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

func AddEmail(db *sql.DB, user *User, email EmailRecord) error {
	metablob, err := cbor.Dumps(email.EmailMetadata)
	if err != nil {
		log.Print("failed to encode email metadata cbor ", err)
		metablob = make([]byte, 0)
	}
	_, err = db.Exec(`INSERT INTO user_email (id, email, data) VALUES ($1, $2, $3)`, user.Guid, email.Email, metablob)
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

func dbIsSqlite(db *sql.DB) bool {
	driver := db.Driver()
	t := reflect.TypeOf(driver)
	return t.Kind() == reflect.Ptr && t.Elem().Name() == "SQLiteDriver"
}

func NewSqlUserDB(db *sql.DB) UserDB {
	if dbIsSqlite(db) {
		return &sqlite3UserDB{db}
	}
	return &postgresUserDB{db}
}

type innerDriver interface {
	PutGuser(tx *sql.Tx, nu *User, pblob []byte) (int64, error)
	GetLocalUser(uid string) (*User, error)
	GetSocialUser(service, id string) (*User, error)
	DB() *sql.DB
}

type postgresUserDB struct {
	db *sql.DB
}

// implement innerDriver
func (sdb *postgresUserDB) PutGuser(tx *sql.Tx, nu *User, pblob []byte) (int64, error) {
	idrows, err := tx.Query(`INSERT INTO guser (username, password, prefs) VALUES ($1, $2, $3) RETURNING id`, nu.Username, nu.Password, pblob)
	if err != nil {
		err = fmt.Errorf("error inserting new user: %s", err)
		return 0, err
	}
	var newGuid int64 = 0
	if idrows.Next() {
		err = idrows.Scan(&newGuid)
		if err != nil {
			err = fmt.Errorf("could not get new guid: %s", err)
			return 0, err
		}
	}
	// This call to Next which doesn't do anything but return
	// false is necssary due to lib/pq driver oddities!
	for idrows.Next() {
		log.Print("bogus extra rows of return from INSERT!")
	}
	return newGuid, err
}

// implement innerDriver
func (sdb *postgresUserDB) DB() *sql.DB {
	return sdb.db
}

func (sdb *postgresUserDB) PutNewUser(nu *User) (*User, error) {
	return commonPutNewUser(sdb, nu)
}

func (sdb *postgresUserDB) GetUser(guid int64) (*User, error) {
	return postgresGetUser(sdb.db, guid)
}
func (sdb *postgresUserDB) GetLocalUser(uid string) (*User, error) {
	return postgresGetLocalUser(sdb.db, uid)
}
func (sdb *postgresUserDB) GetSocialUser(service, id string) (*User, error) {
	return postgresGetSocialUser(sdb.db, service, id)
}

func (sdb *postgresUserDB) SetUserPrefs(xuser *User) error {
	return SetUserPrefs(sdb.db, xuser)
}
func (sdb *postgresUserDB) SetUserPassword(xuser *User) error {
	return SetUserPassword(sdb.db, xuser)
}

// Set local login for a social-login user
func (sdb *postgresUserDB) SetLogin(user *User, username, password string) error {
	return SetLogin(sdb.db, user, username, password)
}

func (sdb *postgresUserDB) AddEmail(user *User, email EmailRecord) error {
	return AddEmail(sdb.db, user, email)
}

func (sdb *postgresUserDB) DelEmail(user *User, email string) error {
	return DelEmail(sdb.db, user, email)
}

func (sdb *postgresUserDB) Feedback(user *User, now int64, text string) error {
	return Feedback(sdb.db, user, now, text)
}

func (sdb *postgresUserDB) Setup() error {
	return postgresCreateTables(sdb.db)
}

func (sdb *postgresUserDB) Close() {
	sdb.db.Close()
	sdb.db = nil
}

type sqlite3UserDB struct {
	db *sql.DB
}

// implement innerDriver
func (sdb *sqlite3UserDB) PutGuser(tx *sql.Tx, nu *User, pblob []byte) (int64, error) {
	result, err := tx.Exec(`INSERT INTO guser (username, password, prefs) VALUES ($1, $2, $3)`, nu.Username, nu.Password, pblob)
	if err != nil {
		err = fmt.Errorf("error inserting new user: %s", err)
		return 0, err
	}
	newGuid, err := result.LastInsertId()
	if err != nil {
		err = fmt.Errorf("could not get user insert rowid, %v", err)
	}
	return newGuid, err
}

// implement innerDriver
func (sdb *sqlite3UserDB) DB() *sql.DB {
	return sdb.db
}

func (sdb *sqlite3UserDB) PutNewUser(nu *User) (*User, error) {
	return commonPutNewUser(sdb, nu)
}

func (sdb *sqlite3UserDB) GetUser(guid int64) (*User, error) {
	cmd := `SELECT g.username, g.password, g.prefs, e.email, e.data, g.ROWID, s.socialkey, s.socialdata FROM guser g LEFT JOIN user_email e ON g.ROWID = e.id LEFT JOIN user_social s ON g.ROWID = s.id WHERE g.ROWID = $1`
	rows, err := sdb.db.Query(cmd, guid)
	if err != nil {
		log.Printf("sql err on %#v: %s", cmd, err)
		return nil, err
	}
	return readUserFromSelect(rows)
}

func (sdb *sqlite3UserDB) GetLocalUser(uid string) (*User, error) {
	cmd := `SELECT g.username, g.password, g.prefs, e.email, e.data, g.ROWID, s.socialkey, s.socialdata FROM guser g LEFT JOIN user_email e ON g.ROWID = e.id LEFT JOIN user_social s ON g.ROWID = s.id WHERE g.username = $1`
	rows, err := sdb.db.Query(cmd, uid)
	if err != nil {
		log.Printf("sql err on %#v: %s", cmd, err)
		return nil, err
	}
	return readUserFromSelect(rows)
}
func (sdb *sqlite3UserDB) GetSocialUser(service, id string) (*User, error) {
	socialkey := SocialKey(service, id)
	cmd := `WITH sq AS (SELECT sqs.id FROM user_social sqs WHERE sqs.socialkey = $1 LIMIT 1) SELECT g.username, g.password, g.prefs, e.email, e.data, g.ROWID, s.socialkey, s.socialdata FROM guser g JOIN sq ON g.ROWID = sq.id LEFT JOIN user_email e ON g.ROWID = e.id LEFT JOIN user_social s ON g.ROWID = s.id`
	rows, err := sdb.db.Query(cmd, socialkey)
	if err != nil {
		log.Printf("sql err on %#v: %s", cmd, err)
		return nil, err
	}
	return readUserFromSelect(rows)
}

func (sdb *sqlite3UserDB) SetUserPrefs(xuser *User) error {
	return SetUserPrefs(sdb.db, xuser)
}
func (sdb *sqlite3UserDB) SetUserPassword(xuser *User) error {
	return SetUserPassword(sdb.db, xuser)
}

// Set local login for a social-login user
func (sdb *sqlite3UserDB) SetLogin(user *User, username, password string) error {
	return SetLogin(sdb.db, user, username, password)
}

func (sdb *sqlite3UserDB) AddEmail(user *User, email EmailRecord) error {
	return AddEmail(sdb.db, user, email)
}

func (sdb *sqlite3UserDB) DelEmail(user *User, email string) error {
	return DelEmail(sdb.db, user, email)
}

func (sdb *sqlite3UserDB) Feedback(user *User, now int64, text string) error {
	return Feedback(sdb.db, user, now, text)
}

func (sdb *sqlite3UserDB) Setup() error {
	return sqlite3CreateTables(sdb.db)
}

func (sdb *sqlite3UserDB) Close() {
	sdb.db.Close()
	sdb.db = nil
}
