package crypto

import cbor "github.com/brianolson/cbor_go"

import "testing"
import "time"

var testAesKey []byte = []byte("0123456789012345")

func TestParseUserCookie(t *testing.T) {
	cookieKey = testAesKey
	var uid int64 = 1234

	xcs := LoginCookieStruct{
		time.Now().Unix(),
		uid,
	}
	xb, _ := cbor.Dumps(xcs)
	xcs2 := LoginCookieStruct{}
	cbor.Loads(xb, &xcs2)
	if xcs2 != xcs {
		t.Errorf("want cs=%#v, got cs2=%#v", xcs, xcs2)
	}

	cstr, err := MakeLoginCookie(uid)
	if err != nil {
		t.Error(err)
	}

	lguid, err := ParseLogin(cstr)
	if err != nil {
		t.Error(err)
	}
	if lguid != uid {
		t.Errorf("uid mismatch want %#v got %#v", uid, lguid)
	}
}

func TestNonce(t *testing.T) {
	cookieKey = testAesKey
	n, err := Nonce()
	if err != nil {
		t.Error(err)
	}
	then, err := GetNonceTime(n)
	if err != nil {
		t.Error(err)
	}
	now := time.Now()
	dt := now.Sub(then)
	if dt > 5*time.Second {
		t.Errorf("time drift %v %v", now, then)
	}
}
