package crypto

import (
	"crypto/aes"
	"crypto/cipher"

	//"crypto/sha256"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"time"

	// TODO: custom encodin/binary cookie instead of cbor
	cbor "github.com/brianolson/cbor_go"
)

var flagCookieKey *string = flag.String("cookie-key", "", "base64 encoded aes key (16,24,32 decoded bytes)")

// TODO: keep a rotating set of server keys, decode incoming cookies against any of them, rotate out the oldest key periodically, re-key user login cookies if they're not on the newest key. 'server key' could also specify different random pad length, different encryption algorithm, different encoded data (not just guid), etc.

var cookieKey []byte

func getkey() []byte {
	// idempotent. doesn't need to be thread safe.
	var err error
	if cookieKey == nil {
		if len(*flagCookieKey) > 0 {
			tk, err := base64.StdEncoding.DecodeString(*flagCookieKey)
			if err != nil {
				log.Print(err)
				return nil
			}
			cookieKey = tk
		} else {
			// generate a key
			nk := make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, nk)
			if err != nil {
				log.Print(err)
				return nil
			}
			cookieKey = nk
			log.Print("new key base64: " + base64.StdEncoding.EncodeToString(cookieKey))
		}
	}
	return cookieKey
}

type LoginCookieStruct struct {
	Time int64 `cbor:"t"`
	Guid int64 `cbor:"u"`
}

const randomPadLength = 8

func MakeLoginCookie(uid int64) (string, error) {
	var err error

	rpad := make([]byte, randomPadLength)
	_, err = io.ReadFull(rand.Reader, rpad)
	if err != nil {
		return "", err
	}
	cs := LoginCookieStruct{
		Time: time.Now().Unix(),
		Guid: uid,
	}
	csbytes, err := cbor.Dumps(cs)
	if err != nil {
		return "", err
	}
	//log.Printf("cs %#v => %#v", cs, csbytes)
	rpad = append(rpad, csbytes...)
	//log.Printf("rp %#v", rpad)
	/*
		nowbytes, err := time.Now().MarshalBinary()
		ubytes := []byte(u.Uid)
		rpad = append(rpad, nowbytes...)
		rpad = append(rpad, ubytes...)
	*/

	return EncryptBytesToB64(rpad)
}

func EncryptBytesToB64(rpad []byte) (string, error) {
	key := getkey()
	ac, err := aes.NewCipher(key)
	bs := ac.BlockSize()
	ciphertext := make([]byte, bs+len(rpad))
	initialValue := ciphertext[:bs]
	_, err = io.ReadFull(rand.Reader, initialValue)
	if err != nil {
		return "", err
	}
	enc := cipher.NewCFBEncrypter(ac, initialValue)
	enc.XORKeyStream(ciphertext[bs:], rpad)
	// TODO: encrypt AND SIGN with hmac

	sout := base64.StdEncoding.EncodeToString(ciphertext)
	//log.Printf("makeUserCookie %d iv, %d cbor -> %d base64", bs, len(rpad), len(sout))
	return sout, nil
}

func B64Decrypt(ucookie string) ([]byte, error) {
	key := getkey()
	defer func() {
		if failed := recover(); failed != nil {
			log.Printf("panic parsing user cookie: %v", failed)
		}
	}()
	ac, err := aes.NewCipher(key)
	bs := ac.BlockSize()

	ciphertext, err := base64.StdEncoding.DecodeString(ucookie)
	if err != nil {
		log.Printf("cookie base64 decode fails %#v %s", ucookie, err)
		return nil, err
	}
	initialValue := ciphertext[:bs]
	ct := ciphertext[bs:]
	//log.Printf("parseUserCookie %d base64 into %d bytes, %d iv %v ct", len(ucookie), len(ciphertext), len(initialValue), len(ct))
	enc := cipher.NewCFBDecrypter(ac, initialValue)
	enc.XORKeyStream(ct, ct)
	return ct, nil
}

func parseUserCookie(ucookie string) (*LoginCookieStruct, error) {
	defer func() {
		if failed := recover(); failed != nil {
			log.Printf("panic parsing user cookie: %v", failed)
		}
	}()

	ct, err := B64Decrypt(ucookie)
	//log.Printf("ct %#v", ct)
	cs := LoginCookieStruct{}
	err = cbor.Loads(ct[randomPadLength:], &cs)
	//log.Printf("cs %#v", cs)
	if err != nil {
		log.Printf("cbor loads err: %s", err)
		return nil, err
	}
	return &cs, nil
}

func ParseLogin(ucookie string) (int64, error) {
	cs, err := parseUserCookie(ucookie)
	if err != nil {
		log.Printf("failure in parseUserCookie %s", err)
		return 0, err
	}
	if cs == nil {
		return 0, err
	}
	// TODO: reject cookies older than [2 weeks?]
	// TODO: reject cookies for a user older than a password change or other log-me-out-everywhere event
	return cs.Guid, err
}

func Nonce() (nonce string, err error) {
	msg := make([]byte, randomPadLength+8)
	_, err = io.ReadFull(rand.Reader, msg[:randomPadLength])
	if err != nil {
		return
	}
	binary.LittleEndian.PutUint64(msg[randomPadLength:], uint64(time.Now().Unix()))
	return EncryptBytesToB64(msg)
}

func GetNonceTime(nonce string) (then time.Time, err error) {
	msg, err := B64Decrypt(nonce)
	if err != nil {
		return
	}
	then = time.Unix(int64(binary.LittleEndian.Uint64(msg[randomPadLength:])), 0)
	return
}
