package login

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	oauth "golang.org/x/oauth2"

	"github.com/brianolson/login/login/crypto"
	"github.com/brianolson/login/login/sql"
)

// ParseConfigJSON reads JSON that should be a dict of {"service name":{oauth2.Config object}}
func ParseConfigJSON(rin io.Reader) (map[string]oauth.Config, error) {
	dec := json.NewDecoder(rin)
	configs := make(map[string]oauth.Config)
	err := dec.Decode(&configs)
	if err != nil {
		return nil, err
	}
	return configs, nil
}

// Configs should be map[string]oauth2.Config from golang.org/x/oauth2
// e.g.
// {"google":{"ClientID":"123-ABC.apps.googleusercontent.com", "ClientSecret":"12345", "Scopes": ["openid", "email"], "Endpoint":{"AuthURL":"https://accounts.google.com/o/oauth2/auth", "TokenURL":"https://accounts.google.com/o/oauth2/token"}, "RedirectURL":"https://myapp.com/login/google/callback"}}
//
// See ParseConfigJSON
func BuildOauthMods(configs map[string]oauth.Config, udb UserDB, homePath string, errPath string) ([]*OauthCallbackHandler, error) {
	authmods := make([]*OauthCallbackHandler, 0)
	logger := slog.Default()
	for serviceName, conf := range configs {
		cb := &OauthCallbackHandler{
			Name:     serviceName,
			Config:   conf,
			Udb:      udb,
			HomeURL:  homePath,
			ErrorURL: errPath,
			logger:   logger,
		}
		authmods = append(authmods, cb)
	}
	for _, cb := range authmods {
		logger.Info("oauth service", "service", cb.Name, "config", cb.Config, "start", cb.StartUrl())
	}
	return authmods, nil
}

// Handler for misc oauth login services. Google, fb, etc.
type OauthCallbackHandler struct {
	Name   string
	Config oauth.Config
	Udb    sql.UserDB

	// HomeURL is the url to redirect to on successful oauth login
	HomeURL string

	// ErrorURL is the url to redirect to on oauth login failure
	ErrorURL string

	logger *slog.Logger

	gkh *GoogleKeyHolder
}

// local path which this Handler should register for
func (cb *OauthCallbackHandler) HandlerUrl() string {
	u, _ := url.Parse(cb.Config.RedirectURL)
	return u.Path
}

// StartUrl is the URL to link so that browser can begin 'log in with Name '
// Returns URL that user's browser should load to start auth
func (cb *OauthCallbackHandler) StartUrl() string {
	csrf, err := makeCSRFStr()
	if err != nil {
		cb.logger.Error("MakeCSRF fail", "err", err)
		csrf = "foo"
	}
	return cb.Config.AuthCodeURL(csrf)
}

// ServeHTTP should handle traffic to the path returned from HandlerUrl()
// This receives data from the service's servers.
// Redirect handler receives state and auth from server.
// config should point oauth other side at this
func (cb *OauthCallbackHandler) ServeHTTP(out http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	ok, err := checkCSRFStr(request.FormValue("state"))
	if err != nil {
		cb.logger.Warn("CSRF check fail", "err", err)
		http.Redirect(out, request, cb.ErrorURL, http.StatusMovedPermanently)
		return
	} else if !ok {
		cb.logger.Warn("CSRF attack?")
		http.Redirect(out, request, cb.ErrorURL, http.StatusMovedPermanently)
		return
	}
	tok, err := cb.Config.Exchange(ctx, request.FormValue("code"))
	if err != nil {
		cb.logger.Warn("oauth callback exchange", "err", err)
		http.Redirect(out, request, cb.ErrorURL, http.StatusMovedPermanently)
		return
	}
	//cb.logger.Info("oauth", "tok", tok)
	//cb.logger.Info("oauth extra", "id_token", "extra['id_token'] ", "extra", tok.Extra("id_token"))
	//cb.logger.Info("avail extra ", "keys", tok.ExtraKeys()) // TODO: submit patch to oauth

	// TODO: subclass? interface?
	if cb.Name == "google" {
		id_tokenp := tok.Extra("id_token")
		if id_tokenp != nil {
			if cb.googleDecodeExtraToken(out, request, id_tokenp) {
				// was handled. done.
				return
			}
		}
		cb.logger.Warn("google without id_token")
	} else if cb.Name == "facebook" {
		// TODO: make this asynchronous? return logged in immediately and fill in extra data into user profile later?
		if cb.facebookGetMoreInfo(out, request, cb.Udb, tok) {
			return
		}
	}

	cb.logger.Warn("TODO: failed to get more info", "service", cb.Name, "url", request.URL.Path)

	http.Redirect(out, request, cb.ErrorURL, http.StatusMovedPermanently)
}

func (cb *OauthCallbackHandler) googleDecodeExtraToken(out http.ResponseWriter, request *http.Request, id_tokenp interface{}) (done bool) {
	id_token, ok := id_tokenp.(string)
	if !ok {
		return false
	}
	keys_json, err := cb.gkh.GetGoogKeysJson()
	if err != nil {
		cb.logger.Warn("failed getting google keys", "err", err)
		return false
	}
	//cb.logger.Warn("got keys_json ", keys_json)
	tsocuser, err := decodeGoogleIdToken(id_token, keys_json)
	if err != nil {
		cb.logger.Warn("failed decoding google id token", "err", err)
		return false
	}
	if tsocuser == nil {
		cb.logger.Warn("decoding google id token got nil tsoc")
		return false
	}
	xu, err := cb.Udb.GetSocialUser(tsocuser.Service, tsocuser.Id)
	if xu == nil {
		cb.logger.Warn("creating db user for social", "service", tsocuser.Service, "id", tsocuser.Id)
		xu = &User{}
		xu.Social = make([]UserSocial, 1)
		xu.Social[0] = *tsocuser
		xu, err = cb.Udb.PutNewUser(xu)
	}
	if (err == nil) && (xu != nil) {
		xuc, err := crypto.MakeLoginCookie(xu.Guid)
		if err != nil {
			cb.logger.Warn("error making cookie", "err", err)
			http.Error(out, "error logging in 110", 500)
			return true
		}
		ucookie := MakeHttpCookie(xuc)
		//cb.logger.Warn("Set Cookie (social login)", "cookie", ucookie.String())
		http.SetCookie(out, ucookie)
		redirCookie, err := request.Cookie("r")
		if err == nil && redirCookie != nil && (len(redirCookie.Value) > 0) {
			http.SetCookie(out, &http.Cookie{Name: "r", MaxAge: -1})
			http.Redirect(out, request, redirCookie.Value, 303)
			return true
		}
		http.Redirect(out, request, cb.HomeURL, 303)
		return true
	}
	if err != nil {
		cb.logger.Warn("social login err", "err", err)
		http.Error(out, "social login error", 500)
		return true
	}
	// caller should fall through to other handling logic
	return false
}

/*
// expected data in facebookGetMoreInfo below
type FbInfo struct {
	Email    string  `json:"email"`
	Name     string  `json:"name"`
	Id       string  `json:"id"`
	Gender   string  `json:"gender"`
	Timezone float64 `json:"timezone"`
}
*/

func dgets(d map[string]interface{}, k string) string {
	v, ok := d[k]
	if !ok {
		return ""
	}
	switch sv := v.(type) {
	case string:
		return sv
	case []byte:
		return string(sv)
	default:
		return ""
	}
}

func (cb *OauthCallbackHandler) facebookGetMoreInfo(out http.ResponseWriter, request *http.Request, udb UserDB, tok *oauth.Token) bool {
	client := cb.Config.Client(oauth.NoContext, tok)
	resp, err := client.Get("https://graph.facebook.com/v2.6/me?fields=email,name,id,gender,timezone")
	if err != nil {
		cb.logger.Warn("failed getting fb me ", "err", err)
		return false
	}

	dec := json.NewDecoder(resp.Body)
	var info map[string]interface{} //FbInfo
	err = dec.Decode(&info)
	if err != nil {
		cb.logger.Warn("failed decoding fb me json ", "err", err)
		return false
	}

	tsoc := UserSocial{
		Service: "facebook",
		Id:      info["id"].(string),
		Data:    info,
	}

	xu, err := cb.Udb.GetSocialUser(tsoc.Service, tsoc.Id)
	if xu == nil {
		cb.logger.Info("creating db social user", "service", tsoc.Service, "id", tsoc.Id)
		xu = &User{}
		xu.Social = make([]UserSocial, 1)
		xu.Social[0] = tsoc
		email := dgets(info, "email")
		if len(email) > 0 {
			xu.Email = make([]EmailRecord, 1)
			xu.Email[0] = NewEmail(email)
		}
		name := dgets(info, "name")
		if len(name) > 0 {
			xu.DisplayName = name
		}
		xu, err = cb.Udb.PutNewUser(xu)
	}
	if (err == nil) && (xu != nil) {
		xuc, err := crypto.MakeLoginCookie(xu.Guid)
		if err != nil {
			cb.logger.Error("error making cookie", "err", err)
			http.Error(out, "error logging in 110", 500)
			return true
		}
		ucookie := MakeHttpCookie(xuc)
		//cb.logger.Info("Set Cookie (social login) ", "cookie", ucookie.String())
		http.SetCookie(out, ucookie)
		redirCookie, err := request.Cookie("r")
		if err == nil && redirCookie != nil {
			http.SetCookie(out, &http.Cookie{Name: "r", MaxAge: -1})
			http.Redirect(out, request, redirCookie.Value, 303)
			return true
		}
		http.Redirect(out, request, cb.HomeURL, 303)
		return true
	}
	if err != nil {
		cb.logger.Warn("facebook login err", "err", err)
		http.Error(out, "facebook login error", 500)
		return true
	}

	return false
}

func (cb *OauthCallbackHandler) String() string {
	return fmt.Sprintf("CbH(%s: %v)", cb.Name, cb.Config)
}

const randomPadLength = 8

func makeCSRFStr() (string, error) {

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

func checkCSRFStr(data string) (bool, error) {
	ct, err := crypto.B64Decrypt(data)
	if err != nil {
		return false, err
	}
	when, _ := binary.Varint(ct[randomPadLength:])
	now := time.Now().Unix()
	ok := (now - when) < MAX_CSRF_TOKEN_SECONDS
	return ok, nil
}
