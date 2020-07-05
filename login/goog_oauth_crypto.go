package login

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"

	"bolson.org/~/src/httpcache"
	//"bolson.org/~/src/login/login/sql"
)

/*
curl --dump-header - https://accounts.google.com/.well-known/openid-configuration
that UNCACHEABLE json has
['authorization_endpoint'] -> AuthURI
['token_endpoint'] -> TokenURI
['jwks_uri'] is this:
curl --dump-header - https://www.googleapis.com/oauth2/v3/certs

Expires: Wed, 27 May 2015 17:28:46 GMT
Date: Wed, 27 May 2015 10:34:46 GMT
Cache-Control: public, max-age=24840, must-revalidate, no-transform
Age: 12852
*/

/*
const keys_json = `{
 "keys": [
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "ae67a0ed4b6d7406004037d8629d7a079cf0231f",
   "n": "s0GsZMFjKB6_N-LfKXHKU8SyT9_aoiCQOG0zx5Dqjnk6wpu5nYfRWVetkVsCYg6dUYqBULkVdVJptSyKt6nWyids1NYIURBeuvyVUvFa__rC_lU7hkyHC2_xajtgf8rk8ybyDrlleGtRHFws1O9iMM9hsUBOAYoHC-a0lCGM4VZuHhUfqFeRRs0X1zQ9vwFWfkq7NvwFD-dL658jR4XqYKyGorfeBtlgIUiQVGJJqDMGbdak63_euc9-QXKuQ6HFxiFunohVMjqk3bHvyvLpVQbR9m83t1ysdfamxsiVH4k0fTLuMUNEscBVUVUxRZpwEFoG_4TlQT5mckTPfBnb-Q",
   "e": "AQAB"
  },
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "f8b8821f7007ef1e9345f2c48e8e46d0d9935a45",
   "n": "xqi8ZdO6vpmgi7LoHdOijSXtWwh6mtPiukHKbXgciSVmcx7HGTapU8A2s9rxHGEA82OgQ3SMcD2bY53boD0nrmiJ1GnYiRjnPf3WYovST9XncJ7-TxTGT4ElBoHYXhsk2boNEmgF9a0i5Hk2pMku23Ac9LdMymKkA3ViLsKM_AL_6rWscULoVhtwQ81cBrmjhKpFyYkRzQHhe7IgmWwiXpLtP_R6cSCdkj7Xtjg1Mjyhne7iFYsXntyyQU1KedrFP3Tc-zcHvcPwMw0j3bUuaV1xEmF16h2UVIHYHMxgmn4IMbDPrJ75dipujt7OsVCNGkM8FAe1h36NJFOSow841w",
   "e": "AQAB"
  }
 ]
}`

*/

var goog_keys_json_cache string
var goog_keys_json_cache_expiretime int64 = 0

var serverCredentialsCachePath string = "server_keys_cache"
var cacheingHttpClient *http.Client
var cacheingHttpClientLock sync.Mutex

func getClient() *http.Client {
	cacheingHttpClientLock.Lock()
	defer cacheingHttpClientLock.Unlock()

	if cacheingHttpClient == nil {
		var err error
		cacheingHttpClient, err = httpcache.NewClient(serverCredentialsCachePath)
		if err != nil {
			log.Printf("error getting caching http client, %v", err)
			return http.DefaultClient
		}
	}
	return cacheingHttpClient
}

func GetGoogKeysJson() (string, error) {
	if (len(goog_keys_json_cache) > 0) && (goog_keys_json_cache_expiretime > 0) && (goog_keys_json_cache_expiretime > time.Now().Unix()) {
		// return cached string
		return goog_keys_json_cache, nil
	}

	client := getClient()
	response, err := client.Get("https://www.googleapis.com/oauth2/v3/certs")
	if err == io.EOF {
		// ok
	} else if err != nil {
		log.Printf("failed to get goog keys json %T %#v %s", err, err, err)
		return "", err
	}
	if response.StatusCode != 200 {
		log.Print("non 200 goog keys json", response.Status)
		return "", errors.New("keys unavailable. http")
	}
	tb, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Print("failed reading goog key json body ", err)
		return "", err
	}
	log.Printf("get keys body len=%d v=%#v", response.ContentLength, string(tb))
	goog_keys_json_cache = string(tb)
	goog_keys_json_cache_expiretime = httpcache.CacheExpirationTime(response)
	return goog_keys_json_cache, nil
}

func padDecode(foo string) ([]byte, error) {
	for (len(foo) % 4) != 0 {
		foo = foo + "="
	}
	return base64.URLEncoding.DecodeString(foo)
}

func jsgets(d map[string]interface{}, k string) (string, bool) {
	raw, ok := d[k]
	if !ok {
		return "", ok
	}
	st, ok := raw.(string)
	return st, ok
}

func decodeGoogleIdToken(id_token, keys_json string) (*UserSocial, error) {
	var ok bool
	var err error

	// use jwt library ...

	// captures keys_json from scope
	keyfunc := func(jtok *jwt.Token) (interface{}, error) {
		keyid, ok := jsgets(jtok.Header, "kid")
		if !ok {
			return nil, nil
		}
		key, err := getGoogleKeyById(keys_json, keyid)
		//log.Printf("gotkey %v %v", key, err)
		return key, err
	}
	jtok, err := jwt.Parse(id_token, keyfunc)
	//log.Print("jtok ", jtok, err)
	claims, ok := jtok.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("jwt Claims is what? %T %#v", jtok.Claims, jtok.Claims)
		return nil, nil
	}
	email, _ := jsgets(claims, "email")
	uid, _ := jsgets(claims, "sub")
	log.Printf("decoded token email=%s uid=%s", email, uid)
	// TODO: check that Claims["aud"] (or "azp"?) == our client id, 235699836956-tv33mvv98bkicqjn9vh928o6pu2t7ig7.apps.googleusercontent.com

	// or do it with my code, probably missing parts.
	parts := strings.Split(id_token, ".")

	// part 0, algorithm and key id
	algjson, err := padDecode(parts[0])
	if err != nil {
		log.Print("id tok pad decode ", err)
		return nil, err
	}
	alg_keyid := make(map[string]interface{})
	err = json.Unmarshal([]byte(algjson), &alg_keyid)
	if err != nil {
		log.Print("id tok json unmarshal ", err)
		return nil, err
	}
	alg, ok := jsgets(alg_keyid, "alg")
	if !ok {
		log.Print("id_token part0 has no \"alg\"")
		return nil, nil
	}
	if alg != "RS256" {
		log.Printf("unknown crypto alg \"%s\"", alg)
		return nil, nil
	}
	keyid, ok := jsgets(alg_keyid, "kid")
	if !ok {
		log.Print("id_token part0 has no key id \"kid\"")
		return nil, nil
	}

	keybytes, err := getGoogleKeyById(keys_json, keyid)
	if (keybytes == nil) || (err != nil) {
		log.Printf("could not get key %s to verify user id token", keyid)
		return nil, err
	}
	//log.Print("pubkey ", keybytes)

	user_json, err := padDecode(parts[1])
	if err != nil {
		log.Print("id tok uj pad decode ", err)
		return nil, err
	}
	sig, err := padDecode(parts[2])
	if err != nil {
		log.Print("id tok sig pad decode ", err)
		return nil, err
	}

	// "RSA256" = RSASSA-PKCS-v1_5 using SHA-256 hash
	hash := sha256.New()
	hash.Write([]byte(parts[0]))
	hash.Write([]byte("."))
	hash.Write([]byte(parts[1]))
	hashed := hash.Sum(nil)
	err = rsa.VerifyPKCS1v15(keybytes, crypto.SHA256, hashed, sig)
	if err != nil {
		log.Print("id token sig verification failed ", err)
		return nil, err
	}
	//log.Print("check sig ", err)

	// part 1, the user data
	userd := make(map[string]interface{})
	err = json.Unmarshal([]byte(user_json), &userd)
	var tusername string
	tusername, ok = jsgets(userd, "sub")
	if ok {
		return &UserSocial{
			Service: "google",
			Id:      tusername,
		}, nil
	}

	return nil, fmt.Errorf("could not find username in: %#v", user_json)
}

func getGoogleKeyById(keys_json, key_id string) (*rsa.PublicKey, error) {
	var err error
	keys := make(map[string]interface{})
	err = json.Unmarshal([]byte(keys_json), &keys)
	if err != nil {
		log.Print("goog key unmarshal ", err, keys_json)
		return nil, err
	}
	keylist, ok := keys["keys"].([]interface{})
	if !ok {
		return nil, nil
	}
	for _, kraw := range keylist {
		kd, ok := kraw.(map[string]interface{})
		if !ok {
			continue
		}
		kid, ok := jsgets(kd, "kid")
		if !ok {
			continue
		}
		if kid != key_id {
			continue
		}
		keyval, ok := jsgets(kd, "n")
		if !ok {
			continue
		}
		Nbytes, err := padDecode(keyval)
		if err != nil {
			continue
		}
		eval, ok := jsgets(kd, "e")
		if !ok {
			continue
		}
		Ebytes, err := padDecode(eval)
		if err != nil {
			continue
		}
		N := &big.Int{}
		N.SetBytes(Nbytes)
		E := big.Int{}
		E.SetBytes(Ebytes)
		return &rsa.PublicKey{N: N, E: int(E.Int64())}, nil
	}

	return nil, nil
}
