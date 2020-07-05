package sql

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"bolson.org/~/src/login/crypto"
	oauth "golang.org/x/oauth2"
)

func loadConfigs(rin io.Reader) (map[string]oauth.Config, error) {
	dec := json.NewDecoder(rin)
	configs := make(map[string]oauth.Config)
	err := dec.Decode(&configs)
	if err != nil {
		return nil, err
	}
	return configs, nil
}

type OauthCallbackHandler struct {
	Name       string
	Config     oauth.Config
	UdbFactory func() (UserDB, error)
	HomePath   string
	ErrorPath  string
}

// local path which this Handler should register for
func (cb *OauthCallbackHandler) handlerUrl() string {
	u, _ := url.Parse(cb.Config.RedirectURL)
	return u.Path
}

// Returns URL that user's browser should load to start auth
func (cb *OauthCallbackHandler) StartUrl() string {
	csrf, err := MakeCSRFStr()
	if err != nil {
		log.Print("MakeCSRF fail ", err)
		csrf = "foo"
	}
	return cb.Config.AuthCodeURL(csrf)
}

// Redirect handler receives state and auth from server.
// config should point oauth other side at this
func (cb *OauthCallbackHandler) ServeHTTP(out http.ResponseWriter, request *http.Request) {
	ok, err := CheckCSRFStr(request.FormValue("state"))
	if err != nil {
		log.Print("CSRF check fail ", err)
	} else if !ok {
		log.Print("CSRF attack?")
		http.Error(out, "err", 400)
		return
	}
	tok, err := cb.Config.Exchange(oauth.NoContext, request.FormValue("code"))
	if err != nil {
		log.Print("oauth callback exchange ", err)
	}
	//log.Print("oauth tok ", tok)
	//log.Print("extra['id_token'] ", tok.Extra("id_token"))
	//log.Print("avail extra ", tok.ExtraKeys()) // TODO: submit patch to oauth
	udb, err := cb.UdbFactory() //OpenDefault()
	defer udb.Close()

	// TODO: subclass?
	if cb.Name == "google" {
		id_tokenp := tok.Extra("id_token")
		if id_tokenp != nil {
			if cb.maybeDecodeExtraToken(out, request, udb, id_tokenp) {
				// was handled. done.
				return
			}
		}
		log.Print("google without id_token")
	} else if cb.Name == "facebook" {
		// TODO: make this asynchronous? return logged in immediately and fill in extra data into user profile later?
		if cb.facebookGetMoreInfo(out, request, udb, tok) {
			return
		}
	}

	log.Print("TODO: failed to get more info ", cb.Name, " ", request.URL.Path)

	http.Redirect(out, request, cb.ErrorPath, 303)
}

func (cb *OauthCallbackHandler) maybeDecodeExtraToken(out http.ResponseWriter, request *http.Request, udb UserDB, id_tokenp interface{}) (done bool) {
	id_token, ok := id_tokenp.(string)
	if !ok {
		return false
	}
	keys_json, err := GetGoogKeysJson()
	if err != nil {
		log.Print("failed getting google keys ", err)
		return false
	}
	//log.Print("got keys_json ", keys_json)
	tsocuser, err := decodeGoogleIdToken(id_token, keys_json)
	if err != nil {
		log.Print("failed decoding google id token ", err)
		return false
	}
	if tsocuser == nil {
		log.Print("decoding google id token got nil tsoc")
		return false
	}
	xu, err := udb.GetSocialUser(tsocuser.Service, tsocuser.Id)
	if xu == nil {
		log.Printf("creating db user for social %s:%s", tsocuser.Service, tsocuser.Id)
		xu = &User{}
		xu.Social = make([]UserSocial, 1)
		xu.Social[0] = *tsocuser
		xu, err = udb.PutNewUser(xu)
	}
	if (err == nil) && (xu != nil) {
		xuc, err := crypto.MakeLoginCookie(xu.Guid)
		if err != nil {
			log.Printf("error making cookie: %s", err)
			http.Error(out, "error logging in 110", 500)
			return true
		}
		ucookie := MakeHttpCookie(xuc)
		//log.Print("Set Cookie (social login) ", ucookie.String())
		http.SetCookie(out, ucookie)
		redirCookie, err := request.Cookie("r")
		if err == nil && redirCookie != nil && (len(redirCookie.Value) > 0) {
			http.SetCookie(out, &http.Cookie{Name: "r", MaxAge: -1})
			http.Redirect(out, request, redirCookie.Value, 303)
			return true
		}
		http.Redirect(out, request, cb.HomePath, 303)
		return true
	}
	if err != nil {
		log.Print("social login err ", err)
		http.Error(out, "social login error", 500)
		return true
	}
	// caller should fall through to other handling logic
	return false
}

type FbInfo struct {
	Email    string  `json:"email"`
	Name     string  `json:"name"`
	Id       string  `json:"id"`
	Gender   string  `json:"gender"`
	Timezone float64 `json:"timezone"`
}

func (cb *OauthCallbackHandler) facebookGetMoreInfo(out http.ResponseWriter, request *http.Request, udb UserDB, tok *oauth.Token) bool {
	client := cb.Config.Client(oauth.NoContext, tok)
	resp, err := client.Get("https://graph.facebook.com/v2.6/me?fields=email,name,id,gender,timezone")
	if err != nil {
		log.Print("failed getting fb me ", err)
		return false
	}

	dec := json.NewDecoder(resp.Body)
	var info FbInfo
	err = dec.Decode(&info)
	if err != nil {
		log.Print("failed decoding fb me json ", err)
		return false
	}

	tsoc := UserSocial{
		"facebook",
		info.Id,
		info,
	}

	xu, err := udb.GetSocialUser(tsoc.Service, tsoc.Id)
	if xu == nil {
		log.Printf("creating db social user %s:%s", tsoc.Service, tsoc.Id)
		xu = &User{}
		xu.Social = make([]UserSocial, 1)
		xu.Social[0] = tsoc
		if len(info.Email) > 0 {
			xu.Email = make([]string, 1)
			xu.Email[0] = info.Email
		}
		if len(info.Name) > 0 {
			xu.DisplayName = &info.Name
		}
		xu, err = udb.PutNewUser(xu)
	}
	if (err == nil) && (xu != nil) {
		xuc, err := crypto.MakeLoginCookie(xu.Guid)
		if err != nil {
			log.Printf("error making cookie: %s", err)
			http.Error(out, "error logging in 110", 500)
			return true
		}
		ucookie := MakeHttpCookie(xuc)
		log.Print("Set Cookie (social login) ", ucookie.String())
		http.SetCookie(out, ucookie)
		redirCookie, err := request.Cookie("r")
		if err == nil && redirCookie != nil {
			http.SetCookie(out, &http.Cookie{Name: "r", MaxAge: -1})
			http.Redirect(out, request, redirCookie.Value, 303)
			return true
		}
		http.Redirect(out, request, cb.HomePath, 303)
		return true
	}
	if err != nil {
		log.Print("facebook login err ", err)
		http.Error(out, "facebook login error", 500)
		return true
	}

	return false
}

func (cb *OauthCallbackHandler) String() string {
	return fmt.Sprintf("CbH(%s: %v)", cb.Name, cb.Config)
}

func BuildOauthMods(fin io.Reader, mux *http.ServeMux, udbFactory func() (UserDB, error), homePath string, errPath string) ([]*OauthCallbackHandler, error) {
	configs, err := loadConfigs(fin)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	//log.Print("building oath modules: ", configs)
	authmods := make([]*OauthCallbackHandler, 0)
	for serviceName, conf := range configs {
		cb := &OauthCallbackHandler{serviceName, conf, udbFactory, homePath, errPath}
		//log.Print(serviceName, conf)
		//log.Print(cb.StartUrl())
		authmods = append(authmods, cb)
		mux.Handle(cb.handlerUrl(), cb)
	}
	for _, cb := range authmods {
		log.Print(cb.Name, cb.Config, cb.StartUrl())
	}
	return authmods, nil
}

const randomPadLength = 8

func MakeCSRFStr() (string, error) {

	rpad := make([]byte, randomPadLength+10)
	_, err := io.ReadFull(rand.Reader, rpad)
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	ilen := binary.PutVarint(rpad[randomPadLength:], now)
	tlen := randomPadLength + ilen
	rpad = rpad[:tlen]

	return crypto.EncryptBytesToB64(rpad)
}

const MAX_CSRF_TOKEN_SECONDS = 300

func CheckCSRFStr(data string) (bool, error) {
	ct, err := crypto.B64Decrypt(data)
	if err != nil {
		return false, err
	}
	when, _ := binary.Varint(ct[randomPadLength:])
	now := time.Now().Unix()
	ok := (now - when) < MAX_CSRF_TOKEN_SECONDS
	return ok, nil
}
