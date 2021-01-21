package cls

import (
	"sync"
)

var NotLogin = struct {
	sync.RWMutex
	url map[string]bool
}{url: make(map[string]bool)}

var ClinetCnt = struct {
	sync.RWMutex
	cnt map[int]int32
}{cnt: make(map[int]int32)}

func SetCountAdd() {

	ClinetCnt.Lock()
	ClinetCnt.cnt[0] += 1
	ClinetCnt.Unlock()
}

func SetCountDel() {
	ClinetCnt.Lock()
	ClinetCnt.cnt[0] -= 1
	ClinetCnt.Unlock()
}

func GetAliveClientCnt() int32 {
	ClinetCnt.RLock()
	cnt := ClinetCnt.cnt[0]
	ClinetCnt.RUnlock()

	return cnt
}

func SetNotLoginUrl(url string) {
	Lprintf(4, "[INFO] set not login url (%s)", url)

	NotLogin.Lock()
	NotLogin.url[url] = true
	NotLogin.Unlock()
}

func GetNotLogin(url string) bool {
	NotLogin.RLock()
	_, ok := NotLogin.url[url]
	NotLogin.RUnlock()

	return ok
}
