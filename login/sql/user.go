package sql

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var BadUserError = errors.New("bad user name & password")

type User struct {
	// primary key
	Guid int64

	// goog, fb, twit, etc.
	Social []UserSocial

	// Local Username must be unique across local users
	Username string
	Password []byte

	// lost password recovery, notifications
	Email []EmailRecord

	// What we show them when we talk to them. "Hi, ____"
	// Need not be unique.
	DisplayName string

	// Serialized by encoding/json or similar
	Data map[string]interface{}
}

type UserSocial struct {
	Service string
	Id      string
	Data    interface{}
}

type EmailMetadata struct {
	Validated bool
	Added     int64 // unix timestamp
	Data      map[string]interface{}
}

type EmailRecord struct {
	Email string
	EmailMetadata
}

func NewEmail(email string) EmailRecord {
	return EmailRecord{
		Email: email,
		EmailMetadata: EmailMetadata{
			Validated: false,
			Added:     time.Now().UTC().Unix(),
		},
	}
}

func (u *User) GoodPassword(qpw string) bool {
	return bcrypt.CompareHashAndPassword(u.Password, []byte(qpw)) == nil
}

func (u *User) SetPassword(npw string) error {
	npwb, err := bcrypt.GenerateFromPassword([]byte(npw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = npwb
	return nil
}

func (u *User) BestDisplayName() string {
	if len(u.DisplayName) > 0 {
		return u.DisplayName
	}
	if len(u.Username) > 0 {
		return u.Username
	}
	if (u.Email != nil) && (len(u.Email) > 0) {
		return u.Email[0].Email
	}
	return fmt.Sprintf("%d", u.Guid)
}

// mostly for use in templates
func (u *User) HasLocalUser() bool {
	return len(u.Username) > 0 && u.Password != nil
}

func (u *User) HasEmail(email string) bool {
	for _, em := range u.Email {
		if em.Email == email {
			return true
		}
	}
	return false
}
