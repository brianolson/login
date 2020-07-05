package sql

import (
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/bcrypt"
)

var BadUserError = errors.New("bad user name & password")

type User struct {
	// primary key
	Guid uint64

	// goog, fb, twit, etc.
	Social []UserSocial

	// Local Username must be unique across local users
	Username *string
	Password []byte

	// lost password recovery, notifications
	// TODO: metadata: verified. verified time. last sent to. chattyness preferences.
	Email []string

	// What we show them when we talk to them. "Hi, ____"
	// Need not be unique.
	DisplayName *string

	// Enabled forms
	Enabled []string

	NextParam uint32
	// other prefs? move misc prefs to a sub struct?

	// Sorted list of features special enabled for this user.
	Features []int
}

type UserSocial struct {
	Service string
	Id      string
	Data    interface{}
}

type EmailMetadata struct {
	Validated bool
	Added     int64
}

func (u *User) GoodPassword(qpw string) bool {
	ok := bcrypt.CompareHashAndPassword(u.Password, []byte(qpw)) == nil
	if ok {
		return ok
	}
	// TODO: disable old password equality check
	return string(u.Password) == qpw
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
	if u.DisplayName != nil {
		return *u.DisplayName
	}
	if u.Username != nil {
		return *u.Username
	}
	if (u.Email != nil) && (len(u.Email) > 0) {
		return u.Email[0]
	}
	return fmt.Sprintf("%d", u.Guid)
}

// mostly for use in templates
func (u *User) HasLocalUser() bool {
	return u.Username != nil && u.Password != nil
}

func (u *User) FeatureEnabled(featureNumber int) bool {
	i := sort.SearchInts(u.Features, featureNumber)
	if (i < len(u.Features)) && (u.Features[i] == featureNumber) {
		return true
	}
	return false
}

func (u *User) SetFeature(featureNumber int, enable bool) {
	i := sort.SearchInts(u.Features, featureNumber)
	if (i < len(u.Features)) && (u.Features[i] == featureNumber) {
		if enable {
			// already there, done
			return
		} else {
			// disable
			copy(u.Features[i:len(u.Features)-1], u.Features[i+1:len(u.Features)])
			u.Features = u.Features[:len(u.Features)-1]
			return
		}
	}
	if !enable {
		// already not there, done
		return
	}
	// add to enable list
	u.Features = append(u.Features, featureNumber)
	sort.Ints(u.Features)
}

// Feature enum:
const (
	FEATURE_amazonPay = 1
)

// for templates
func (u *User) AmazonPayEnalbed() bool {
	return u.FeatureEnabled(FEATURE_amazonPay)
}
