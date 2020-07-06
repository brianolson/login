package login

import (
	"log"
	"net/http"

	"bolson.org/~/src/login/login/crypto"
)

func cookieGetUser(request *http.Request, udb UserDB) (*User, error) {
	cx, err := request.Cookie("u")
	if err == http.ErrNoCookie {
		//log.Print("no user cookie")
		return nil, nil
	}
	if err != nil {
		//log.Print("err getting cookie ", err)
		return nil, err
	}
	uid, err := crypto.ParseLogin(cx.Value)
	if err != nil {
		return nil, err
	}
	return udb.GetUser(uid)
}

func formGetUser(out http.ResponseWriter, request *http.Request, udb UserDB) (*User, error) {
	var err error
	err = request.ParseForm() //parseForm(request)
	if err != nil {
		log.Print(err)
		return nil, err
	}
	username := request.Form.Get("name")
	if len(username) == 0 {
		return nil, nil
	}
	password := request.Form.Get("pass")

	dbuser, err := udb.GetLocalUser(username)
	if err != nil {
		return nil, err
	}
	if dbuser == nil {
		return nil, BadUserError
	}
	if dbuser.GoodPassword(password) {
		xuc, err := crypto.MakeLoginCookie(dbuser.Guid)
		if err == nil {
			ucookie := MakeHttpCookie(xuc)
			//log.Print("Set Cookie (form login) ", ucookie.String())
			http.SetCookie(out, ucookie)
		} else {
			log.Print(err)
		}
		return dbuser, nil
	} else {
		//log.Printf("bad pass, wanted '%s' got '%s'", dbuser.Password, password)
		return nil, BadUserError
	}
}

// Checkes request for cookier or form login.
// May set cookie in response if form login is successful.
func GetHttpUser(out http.ResponseWriter, request *http.Request, udb UserDB) (*User, error) {
	user, err := cookieGetUser(request, udb)
	if user != nil {
		return user, err
	}
	user, err = formGetUser(out, request, udb)
	return user, err
}

func MakeHttpCookie(xuc string) *http.Cookie {
	return &http.Cookie{Name: "u", Value: xuc, MaxAge: 14 * 24 * 3600, Path: "/"}
}

// Clear cookie. Redirect to /
func LogoutHandler(out http.ResponseWriter, request *http.Request) {
	// TODO: require nonce
	// TODO: configurable redirect destination
	xcookie := &http.Cookie{Name: "u", MaxAge: -1}
	//log.Print("LOGOUT Cookie ", xcookie.String())
	http.SetCookie(out, xcookie)
	http.Redirect(out, request, "/", 303)
}
