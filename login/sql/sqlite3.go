package sql

import "database/sql"

func sqlite3CreateTables(db *sql.DB) error {
	cmds := []string{
		//createGuser, -- override postgres:
		// serial id int is builtin ROWID
		`CREATE TABLE IF NOT EXISTS guser (
username varchar(100), -- may be NULL
password BLOB, -- may be NULL
prefs BLOB -- cbor encoded UserSqlPrefs{}
)`,
		createGuserNameIndex,
		createUserSocial,
		createUserSocialKeyIndex,
		createUserEmail,
		creaetUserEmailIndex,
	}
	return dbTxCmdList(db, cmds)
}
