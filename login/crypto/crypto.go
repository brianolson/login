package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"sync"

	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"time"

	// TODO: custom encodin/binary cookie instead of cbor
	cbor "github.com/brianolson/cbor_go"
)

// TODO: keep a rotating set of server keys, decode incoming cookies against any of them, rotate out the oldest key periodically, re-key user login cookies if they're not on the newest key. 'server key' could also specify different random pad length, different encryption algorithm, different encoded data (not just guid), etc.

var cookieKey []byte
var cookieKeyLock sync.RWMutex

const CookieKeyByteLen = 16

// Generate a new random key and set it and return it
func GenerateCookieKey() []byte {
	cookieKeyLock.Lock()
	defer cookieKeyLock.Unlock()
	nk := make([]byte, CookieKeyByteLen)
	_, err := io.ReadFull(rand.Reader, nk)
	if err != nil {
		log.Print(err)
		return nil
	}
	cookieKey = nk
	//log.Print("new key base64: " + base64.StdEncoding.EncodeToString(cookieKey))
	return cookieKey
}

var ErrKeyWrongLength = errors.New("key not 16 bytes")

func SetCookieKey(key []byte) error {
	if len(key) != CookieKeyByteLen {
		return ErrKeyWrongLength
	}
	cookieKeyLock.Lock()
	defer cookieKeyLock.Unlock()
	cookieKey = key
	return nil
}

func getkey() []byte {
	var k []byte
	cookieKeyLock.RLock()
	k = cookieKey
	cookieKeyLock.RUnlock()
	if k != nil {
		return k
	}
	out := GenerateCookieKey()
	log.Print("new key base64: " + base64.StdEncoding.EncodeToString(out))
	return out
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
	enc, err := cipher.NewGCM(ac)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, enc.NonceSize()+enc.Overhead()+len(rpad))
	nonce := ciphertext[:enc.NonceSize()]
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}
	ciphertext = enc.Seal(nonce, nonce, rpad, nil)

	sout := base64.StdEncoding.EncodeToString(ciphertext)
	//log.Printf("makeUserCookie %d iv, %d cbor -> %d base64", bs, len(rpad), len(sout))
	return sout, nil
}

func B64Decrypt(ucookie string) ([]byte, error) {
	defer func() {
		if failed := recover(); failed != nil {
			log.Printf("panic parsing user cookie: %v", failed)
		}
	}()
	ciphertext, err := base64.StdEncoding.DecodeString(ucookie)
	if err != nil {
		log.Printf("cookie base64 decode fails %#v %s", ucookie, err)
		return nil, err
	}
	// TODO: keep private keys for as long as login cookies may be valid, generate new keys, try decrypt against key history
	key := getkey()
	return decryptForKey(key, ciphertext)
}

func decryptForKey(key, ciphertext []byte) ([]byte, error) {
	ac, err := aes.NewCipher(key)
	enc, err := cipher.NewGCM(ac)
	if err != nil {
		return nil, err
	}

	nlen := enc.NonceSize()
	nonce := ciphertext[:nlen]
	ct := ciphertext[nlen:]
	plaintext, err := enc.Open(nil, nonce, ct, nil)
	return plaintext, err
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

func ParseLogin(ucookie string) (uid, loginTime int64, err error) {
	cs, err := parseUserCookie(ucookie)
	if err != nil {
		log.Printf("failure in parseUserCookie %s", err)
		return 0, 0, err
	}
	if cs == nil {
		return 0, 0, err
	}
	return cs.Guid, cs.Time, err
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
