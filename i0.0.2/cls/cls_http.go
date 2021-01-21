package cls

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	"github.com/julienschmidt/httprouter"
	"github.com/unrolled/render"
	"github.com/urfave/negroni"
)

type PageData struct {
	pName string
	pData map[string]string
}

type AppPages struct {
	Mode    int
	UriName string
	Ufc     func(http.ResponseWriter, *http.Request, httprouter.Params)
	Data    map[string]string
}

var Renderer *render.Render
var pageMap map[string]PageData
var WebHome, WebPort, WebLogin, WebHttps, HttpsCert string
var idMgmt map[string]string

const (
	sessionSecret = "cls_session_secret"
	sessionKey    = "cls_session"
	nextPageKey   = "cls_nextPage"
)

const (
	currentUserKey  = "cls_oauth2_cuser"
	sessionDuration = time.Hour
)

type User struct {
	Uid     string    `json:"uid"`
	Alterid string    `json:"avatar_url"`
	AppData string    `json:"appdata"`
	Expired time.Time `json:"expired"`
}

func Http_start(ap []AppPages, logins []AppPages) {
	Http_startWithState(ap, logins, nil)
}

func Http_startWithState(ap []AppPages, logins []AppPages, connHandler func(net.Conn, http.ConnState)) {
	Http_startWithConfig(ap, logins, "", nil, "", "")
}

func Http_startWithStateIP(ap []AppPages, logins []AppPages, ip string, connHandler func(net.Conn, http.ConnState)) {
	Http_startWithConfig(ap, logins, ip, nil, "", "")
}

func Http_startWithConfig(ap []AppPages, logins []AppPages, newListenIp string, connHandler func(net.Conn, http.ConnState), lDel, rDel string) {
	var pMap PageData

	if lDel == "" {
		Renderer = render.New(render.Options{
			Directory:  WebHome + "/templates",
			Extensions: []string{".tmpl", ".html"},
			// 서버에서 응답 데이터가 html 이면 autoescaping 이 되어 escape 문자가 응답으로 내려감.
			// html 데이터 key는 "htmlSafe", value는 "text"
			Funcs: []template.FuncMap{
				{
					"htmlSafe": func(text string) template.HTML {
						//Lprintf(4, "[INFO] htmlSafe text : %s\n", text)
						return template.HTML(text)
					},
				},
			},
		})
	} else {
		var delims render.Delims
		delims.Left = lDel
		delims.Right = rDel

		Renderer = render.New(render.Options{
			Directory:  WebHome + "/templates",
			Extensions: []string{".tmpl", ".html"},
			Delims:     delims,
			// 서버에서 응답 데이터가 html 이면 autoescaping 이 되어 escape 문자가 응답으로 내려감.
			// html 데이터 key는 "htmlSafe", value는 "text"
			Funcs: []template.FuncMap{
				{
					"htmlSafe": func(text string) template.HTML {
						//Lprintf(4, "[INFO] htmlSafe text : %s\n", text)
						return template.HTML(text)
					},
				},
			},
		})
	}

	router := httprouter.New()
	pageMap = make(map[string]PageData)

	Lprintf(4, "[INFO] start web Setting  pages cnt [%d]", len(ap))
	for i := 0; i < len(ap); i++ {
		wUri := ap[i].UriName
		switch ap[i].Mode {
		case GET:
			if ap[i].Ufc == nil {
				wDir := WebHome + ap[i].UriName + "/"
				wUri = wUri + "/*filepath"
				Lprintf(4, "[INFO] set static URI [%s], DIR [%s]", wUri, wDir)
				router.ServeFiles(wUri, http.Dir(wDir))
			} else {
				Lprintf(4, "[INFO] set URI [%s]", wUri)
				router.GET(wUri, ap[i].Ufc)
			}
		case PAGE:
			ret := strings.Split(ap[i].UriName, ",")
			if len(ret) != 2 { // comma가 없으면 마지막 uri를 그대로 file명으로 쓴다.
				ret = strings.Split(ap[i].UriName, "/")
				wUri = ap[i].UriName
			} else {
				wUri = ret[0]
			}

			pMap.pName = ret[len(ret)-1]
			pMap.pData = ap[i].Data
			pageMap[wUri] = pMap

			Lprintf(4, "[INFO] common page randering name wUri (%s) (%s) ", wUri, pMap.pName)
			router.GET(wUri, renderPage)
		case PUT:
			if ap[i].Ufc != nil {
				router.PUT(wUri, ap[i].Ufc)
			} else {
				Lprintf(1, "[FAIL] PUT handler is NULL ")
				return
			}
		case POST:
			if ap[i].Ufc != nil {
				router.POST(wUri, ap[i].Ufc)
			} else {
				Lprintf(1, "[FAIL] PUT handler is NULL ")
				return
			}
		case DEL:
			if ap[i].Ufc != nil {
				router.DELETE(wUri, ap[i].Ufc)
			} else {
				Lprintf(1, "[FAIL] PUT handler is NULL ")
				return
			}
		default:
			Lprintf(1, "[FAIL] UNKWNON METHOD [%d]", ap[i].Mode)
			return
		}
	}

	n := negroni.Classic()
	for i := 0; i < len(logins); i++ {
		if logins[i].Mode == LOGIN {

			Lprintf(4, "[INFO] login page arg  (%s) ", logins[i].UriName)
			ret := strings.Split(logins[i].UriName, ",")
			if len(ret) != 2 { // comma가 없으면 마지막 uri를 그대로 file명으로 쓴다.
				WebLogin = logins[i].UriName
				ret = strings.Split(logins[i].UriName, "/")
			} else {
				WebLogin = ret[0]
			}
			pMap.pName = ret[len(ret)-1]
			pageMap[WebLogin] = pMap
			Lprintf(4, "[INFO] login page randering name wUri (%s) (%s) ", WebLogin, pMap.pName)

			if logins[i].Ufc != nil {
				router.GET(WebLogin, logins[i].Ufc)
			} else {
				router.GET(WebLogin, renderPage)
			}

		} else if logins[i].Mode == LOGOUT {
			wUri := logins[i].UriName
			if logins[i].Ufc != nil {
				router.GET(wUri, logins[i].Ufc)
			} else {
				router.GET(wUri, renderLogoutPage)
			}

		} else if logins[i].Mode == EXCEPT {
			ret := strings.Split(logins[i].UriName, ",")
			n.Use(LoginCheck(ret))

		} else {
			Lprintf(1, "[FAIL] WRONG LOGIN OPTION (%d)", logins[i].Mode)
			return
		}

		idMgmt = make(map[string]string)
		store := cookiestore.New([]byte(sessionSecret))
		n.Use(sessions.Sessions(sessionKey, store))
	}

	n.UseHandler(router)

	if WebPort != "0" {
		ret := strings.Split(WebPort, ",")
		i := 0
		for ; i < len(ret)-1; i++ {
			Lprintf(4, "[INFO] LISTEN http(%s,i(%d))", ret[i], i)
			go n.Run(":" + ret[i])
		}

		Lprintf(4, "[INFO] LISTEN http(%s,%s)", newListenIp, ret[i])

		//server := &http.Server{Addr: ListenIP + ":" + ret[i], Handler: n, ConnState: connHandler}
		//	if newListenIp != "" {
		//	}
		server := &http.Server{Addr: newListenIp + ":" + ret[i], Handler: n, ConnState: connHandler}
		//}

		//server := &http.Server{Addr: ":" + ret[i], Handler: n, ConnState: connHandler}
		if WebHttps == "0" { // http 단독
			server.ListenAndServe()
			//n.Run(":" + ret[i])
		} else {
			go server.ListenAndServe()
			//go n.Run(":" + ret[i])
		}
	}

	if WebHttps != "0" {
		ret := strings.Split(WebHttps, ",")
		i := 0
		server := &http.Server{Addr: ":" + ret[i], Handler: n, ConnState: connHandler}
		//server.TLSConfig.MinVersion = tls.VersionTLS12

		for ; i < len(ret)-1; i++ {
			Lprintf(4, "[INFO] LISTEN https(%s)", ret[i])
			go server.ListenAndServeTLS(HttpsCert+".crt", HttpsCert+".key")
		}

		Lprintf(4, "[INFO] LISTEN https(%s)", ret[i])
		// http.ListenAndServeTLS(":"+ret[i], "server.crt", "server.key", n)
		server.ListenAndServeTLS(WebHome+"/"+HttpsCert+".crt", WebHome+"/"+HttpsCert+".key")
	}
}

func renderLogoutPage(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	sessions.GetSession(r).Delete(currentUserKey)
	http.Redirect(h, r, WebLogin, http.StatusFound)

}

func renderPage(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	page := pageMap[r.RequestURI]
	Lprintf(4, "[INFO] req URI(%s) Render page (%s) ", r.RequestURI, page.pName)
	Renderer.HTML(h, http.StatusOK, page.pName, page.pData)
}

func (u *User) Valid() bool {
	if idMgmt[u.Uid] != u.Alterid {
		Lprintf(4, "[INFO] Alter id is different map(%s) <-> sses(%s)", idMgmt[u.Uid], u.Alterid)
		return false
	}

	return u.Expired.Sub(time.Now()) > 0
}

func (u *User) Refresh() {
	u.Expired = time.Now().Add(sessionDuration)
}

func GetCurrentUser(r *http.Request) *User {
	var u User
	s := sessions.GetSession(r)

	if s.Get(currentUserKey) == nil {
		return nil
	}

	data := s.Get(currentUserKey).([]byte)
	json.Unmarshal(data, &u)
	return &u
}

func SetCurrentUser(r *http.Request, u *User) {
	if u != nil {
		u.Refresh()
	}

	s := sessions.GetSession(r)
	val, _ := json.Marshal(u)
	s.Set(currentUserKey, val)
}

// login 후 강제 이동
func SuccLoginPage(h http.ResponseWriter, r *http.Request, id, nextPage string) {
	tm := time.Now().String()
	skey := ShaEncode([]byte(tm + id))

	u := &User{
		Uid:     id,
		Alterid: skey,
	}
	idMgmt[id] = skey

	SetCurrentUser(r, u)

	//http.Redirect(h, r, nextPage, http.StatusFound)
	http.Redirect(h, r, nextPage, http.StatusOK)
}

// login 후 접근하고자 하는 이전 페이지 이동
func SuccLogin(h http.ResponseWriter, r *http.Request, id string) {
	tm := time.Now().String()
	skey := ShaEncode([]byte(tm + id))

	u := &User{
		Uid:     id,
		Alterid: skey,
	}
	idMgmt[id] = skey

	SetCurrentUser(r, u)

	s := sessions.GetSession(r)
	nextPage := s.Get(nextPageKey).(string)
	if len(nextPage) == 0 || nextPage == WebLogin {
		nextPage = "/"
	}
	http.Redirect(h, r, nextPage, http.StatusFound)
}

func FailLoginPage(h http.ResponseWriter, r *http.Request, nextPage string) {
	http.Redirect(h, r, nextPage, http.StatusFound)
}

/*
func FailLogin(h http.ResponseWriter, r *http.Request) {
	http.Redirect(h, r, WebLogin, http.StatusFound)
}
*/

func FailLogin(h http.ResponseWriter, r *http.Request, flag int) {
	//Lprintf(1, "[INFO] flag : %d, alertMsg : %s, page : %s\n", flag, alertMsg, page)
	if flag == 0 {
		http.Redirect(h, r, WebLogin, http.StatusFound)
	} else {
		http.Redirect(h, r, WebLogin, http.StatusInternalServerError)
	}
}

func LoginCheck(ig []string) negroni.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		for i := 0; i < len(ig); i++ {
			if strings.HasPrefix(r.URL.Path, ig[i]) {
				next(w, r)
				return
			}
		}

		u := GetCurrentUser(r)
		Lprintf(4, "[INFO] session info (%p) ", u)

		if u != nil && u.Valid() {
			SetCurrentUser(r, u)
			next(w, r)
			return
		}

		SetCurrentUser(r, nil)
		sessions.GetSession(r).Set(nextPageKey, r.URL.RequestURI())
		http.Redirect(w, r, WebLogin, http.StatusFound)
	}
}

func SetServerIp(service PROTOCOL, ips string) bool {

	// get target server info
	for _, value := range CfgServers {
		if value.serverInfo.service == service {
			if len(value.multiServers) > 1 {
				Lprintf(1, "[FAIL] use multi server function") // not made yet
				return false
			}

			// active - stand by
			if value.serverInfo.forwardType == AS {
				value.multiServers[0].forwardServers[0].ipaddr = ips
				return true

			} else if value.serverInfo.forwardType == RR {
				ip := strings.Split(ips, "^")
				fss := value.multiServers[0].forwardServers
				for i := 0; i < len(fss); i++ {
					fss[i].ipaddr = ip[i%len(ip)]
				}

				return true
			}
		}
	}
	Lprintf(1, "[FAIL] cannot find proper server") // not made yet
	return false
}

func GetServerIp(service PROTOCOL) (bool, ServerInfo) {
	var rSinfo ServerInfo

	// get target server info
	for _, value := range CfgServers {
		if value.serverInfo.service == service {
			if len(value.multiServers) > 1 {
				Lprintf(1, "[FAIL] use multi server function") // not made yet
				return false, rSinfo
			}

			// active - stand by
			if value.serverInfo.forwardType == AS {
				return true, value.multiServers[0].forwardServers[0]

			} else if value.serverInfo.forwardType == RR {
				fss := value.multiServers[0].forwardServers

				var totalPri, maxPri, maxIdx uint
				for i := 0; i < len(fss); i++ {
					fsi := fss[i]
					totalPri += fsi.nowPriority
					if fsi.nowPriority > maxPri {
						maxPri = fsi.nowPriority
						maxIdx = uint(i)
					}
				}

				// select forward server and reduce priority
				fss[maxIdx].nowPriority -= 1
				totalPri -= 1

				// recharge priroity
				if totalPri == 0 {
					for i := 0; i < len(fss); i++ {
						fss[i].nowPriority = fss[i].originPriority
					}
				}

				return true, value.multiServers[0].forwardServers[maxIdx]
			}
		}
	}
	Lprintf(1, "[FAIL] can not find service")
	return false, rSinfo
}

const (
	TIMEOUT_CONNECTION = 2
	TIMEOUT_RESPONSE   = 3
)

// just send
func HttpSend(service PROTOCOL, method, fqdn string, close bool) (*http.Response, error) {
	return HttpSendRequestDetail(service, method, fqdn, nil, nil, "", close)
}

// with text body
func HttpSendBody(service PROTOCOL, method, fqdn string, body []byte, close bool) (*http.Response, error) {
	return HttpSendRequestDetail(service, method, fqdn, body, nil, "", close)
}

// with json body
func HttpSendJSON(service PROTOCOL, method, fqdn string, body []byte, close bool) (*http.Response, error) {
	return HttpSendRequestDetail(service, method, fqdn, body, nil, "application/json", close)
}

// with header and json body
func HttpSendRequestJSON(service PROTOCOL, method, fqdn string, body []byte, reqHeader map[string]string, close bool) (*http.Response, error) {
	return HttpSendRequestDetail(service, method, fqdn, body, reqHeader, "application/json", close)
}

// with header
func HttpSendRequest(service PROTOCOL, method, fqdn string, body []byte, reqHeader map[string]string) (*http.Response, error) {
	return HttpSendRequestDetail(service, method, fqdn, body, reqHeader, "", false)
}

// with header and body
func HttpSendHeader(service PROTOCOL, method, fqdn string, body []byte, reqHeader map[string]string, close bool) (*http.Response, error) {
	return HttpSendRequestDetail(service, method, fqdn, body, reqHeader, "", close)
}

// http_requset with body, header
func HttpSendRequestDetail(service PROTOCOL, method, fqdn string, body []byte, reqHeader map[string]string, contentType string, close bool) (*http.Response, error) {
	var address string
	// get target server info
	ok, sInfo := GetServerIp(service)
	if !ok {
		Lprintf(1, "[FAIL] error occur to find Server ")
	}

	Lprintf(4, "[INFO] target server address(%s) \n", sInfo.ipaddr)

	// get target ip
	targetIp := strings.Split(sInfo.ipaddr, "&")
	for i := 0; i < len(targetIp); i++ {
		ip := targetIp[(SvrIdx+i)%len(targetIp)]

		var netTransport = &http.Transport{
			Dial: (&net.Dialer{
				Timeout: TIMEOUT_CONNECTION * time.Second,
			}).Dial,
			TLSHandshakeTimeout: TIMEOUT_CONNECTION * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}

		// client object
		client := &http.Client{
			Timeout:   time.Second * TIMEOUT_RESPONSE,
			Transport: netTransport,
		}

		if sInfo.service == TCP_HTTP {
			address = fmt.Sprintf("http://%s:%d/%s", ip, sInfo.port, fqdn)
		} else if sInfo.service == TCP_HTTPS {
			address = fmt.Sprintf("https://%s:%d/%s", ip, sInfo.port, fqdn)
		} else {
			address = fmt.Sprintf("http://%s:%d/%s", ip, sInfo.port, fqdn)
		}

		Lprintf(4, "[INFO] cls http send address (%s) \n", address)

		// make requset
		req, err := http.NewRequest(method, address, bytes.NewBuffer(body))
		if err != nil {
			Lprintf(1, "[ERROR] http NewRequest error(%s) \n", err.Error())
			return nil, err
		}

		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		if close {
			req.Header.Set("Connection", "close")
		}

		// set request header
		if reqHeader != nil {
			for name, value := range reqHeader {
				req.Header.Set(name, value)
			}
		}

		// client transport
		resp, err := client.Do(req)
		if err != nil {
			Lprintf(1, "[ERROR] http client do error(%s) \n", err.Error())
			// host not found : no such host
			// con close : connection refused
			// client timeout : Timeout exceeded
			if strings.Contains(err.Error(), "connection refused") { // next target
				continue
			} else { // try again
				resp, err = client.Do(req)
				if err != nil { // next target
					continue
				}
			}
		}
		Lprintf(4, "[INFO] cls http send address (%s) finished \n", address)
		return resp, err
	}

	return nil, errors.New("can not find proper target")
}

func Http_startWithConfig_dnstat(ap []AppPages, connHandler func(net.Conn, http.ConnState), httpPort, httpsPort string) {
	var pMap PageData

	Renderer = render.New(render.Options{
		Directory:  WebHome + "/templates",
		Extensions: []string{".tmpl", ".html"},
		// 서버에서 응답 데이터가 html 이면 autoescaping 이 되어 escape 문자가 응답으로 내려감.
		// html 데이터 key는 "htmlSafe", value는 "text"
		Funcs: []template.FuncMap{
			{
				"htmlSafe": func(text string) template.HTML {
					//Lprintf(4, "[INFO] htmlSafe text : %s\n", text)
					return template.HTML(text)
				},
			},
		},
	})

	router := httprouter.New()
	pageMap = make(map[string]PageData)

	Lprintf(4, "[INFO] start web Setting  pages cnt [%d]", len(ap))
	for i := 0; i < len(ap); i++ {
		wUri := ap[i].UriName
		switch ap[i].Mode {
		case GET:
			if ap[i].Ufc == nil {
				wDir := WebHome + ap[i].UriName + "/"
				wUri = wUri + "/*filepath"
				Lprintf(4, "[INFO] set static URI [%s], DIR [%s]", wUri, wDir)
				router.ServeFiles(wUri, http.Dir(wDir))
			} else {
				Lprintf(4, "[INFO] set URI [%s]", wUri)
				router.GET(wUri, ap[i].Ufc)
			}
		case PAGE:
			ret := strings.Split(ap[i].UriName, ",")
			if len(ret) != 2 { // comma가 없으면 마지막 uri를 그대로 file명으로 쓴다.
				ret = strings.Split(ap[i].UriName, "/")
				wUri = ap[i].UriName
			} else {
				wUri = ret[0]
			}

			pMap.pName = ret[len(ret)-1]
			pMap.pData = ap[i].Data
			pageMap[wUri] = pMap

			Lprintf(4, "[INFO] common page randering name wUri (%s) (%s) ", wUri, pMap.pName)
			router.GET(wUri, renderPage)
		case PUT:
			if ap[i].Ufc != nil {
				router.PUT(wUri, ap[i].Ufc)
			} else {
				Lprintf(1, "[FAIL] PUT handler is NULL ")
				return
			}
		case POST:
			if ap[i].Ufc != nil {
				router.POST(wUri, ap[i].Ufc)
			} else {
				Lprintf(1, "[FAIL] PUT handler is NULL ")
				return
			}
		case DEL:
			if ap[i].Ufc != nil {
				router.DELETE(wUri, ap[i].Ufc)
			} else {
				Lprintf(1, "[FAIL] PUT handler is NULL ")
				return
			}
		default:
			Lprintf(1, "[FAIL] UNKWNON METHOD [%d]", ap[i].Mode)
			return
		}
	}

	n := negroni.Classic()

	n.UseHandler(router)

	if httpPort != "0" {
		ret := strings.Split(httpPort, ",")
		i := 0
		for ; i < len(ret)-1; i++ {
			Lprintf(4, "[INFO] LISTEN http(%s,i(%d))", ret[i], i)
			go n.Run(":" + ret[i])
		}
		server := &http.Server{Addr: ":" + ret[i], Handler: n, ConnState: connHandler}

		if httpsPort == "0" || httpsPort == "" { // http 단독
			server.ListenAndServe()
			//n.Run(":" + ret[i])
		} else {
			go server.ListenAndServe()
			//go n.Run(":" + ret[i])
		}
	}

	if httpsPort != "0" {
		ret := strings.Split(httpsPort, ",")
		i := 0
		server := &http.Server{Addr: ":" + ret[i], Handler: n, ConnState: connHandler}

		for ; i < len(ret)-1; i++ {
			Lprintf(4, "[INFO] LISTEN https(%s)", ret[i])
			go server.ListenAndServeTLS(HttpsCert+".crt", HttpsCert+".key")
		}

		Lprintf(4, "[INFO] LISTEN https(%s)", ret[i])
		// http.ListenAndServeTLS(":"+ret[i], "server.crt", "server.key", n)
		//	cert := WebHome + "/" + HttpsCert + ".crt"
		//	Lprintf(4, "cert(%s)", cert)
		server.ListenAndServeTLS(WebHome+"/"+HttpsCert+".crt", WebHome+"/"+HttpsCert+".key")
	}
}
