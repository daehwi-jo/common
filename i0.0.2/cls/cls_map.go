package cls

import (
	"net"
	"sync"
)

const MapCap = 1024

var ClinetCnt = struct {
	sync.RWMutex
	cnt map[int]int32
}{cnt: make(map[int]int32)}

var ShareMap = struct {
	sync.RWMutex
	sData map[string]string
}{sData: make(map[string]string, MapCap)}

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

func Search(key string) (bool, string) {
	ShareMap.RLock()
	value, exist := ShareMap.sData[key]
	ShareMap.RUnlock()

	if !exist {
		return false, ""
	}

	return true, value
}

func SearchDelete(key string) (bool, string) {

	ShareMap.Lock()
	value, exist := ShareMap.sData[key]
	if exist {
		delete(ShareMap.sData, key)
	}
	ShareMap.Unlock()

	if !exist {
		return false, ""
	}

	return true, value
}

func Insert(key, data string) bool {
	ShareMap.Lock()
	_, exist := ShareMap.sData[key]
	if !exist {
		ShareMap.sData[key] = data
	}
	ShareMap.Unlock()

	return !exist
}

func InsertForce(key, data string) bool {
	ShareMap.Lock()
	ShareMap.sData[key] = data
	ShareMap.Unlock()

	return true
}

func Delete(key string) bool {
	ShareMap.Lock()
	delete(ShareMap.sData, key)
	ShareMap.Unlock()

	return true
}

func ListenMap(laddr string) bool {
	listener, err := net.Listen("tcp", laddr)
	if err != nil {
		Lprintf(1, "[FAIL] listen error (%s) ", err)
		return false
	}
	defer listener.Close()

	for {
		// listen and accept
		Lprintf(4, "[INFO] listen client(%s)", laddr)
		conn, err := listener.Accept()
		if err != nil {
			Lprintf(1, "[FAIL] tcp proxy listen fail(%s)", err)
			return false
		}

		Lprintf(4, "[INFO] map service connected")
		go mapService(conn, true)
	}

}

// 25 자 고정통신
func mapService(lcon net.Conn, connect bool) {

	packetSize := 25

	hBuf := make([]byte, packetSize)
	hLen, err := lcon.Read(hBuf)
	if err != nil {
		Lprintf(1, "[FAIL] map service header read fail(%s)", err)
		return
	}
	// read header at least
	for hLen < packetSize {
		len, err := lcon.Read(hBuf[hLen:])
		if err != nil {
			Lprintf(1, "[FAIL] map service header read fail(%s)", err)
			return
		}
		hLen = hLen + len
	}

	i := 0
	for ; i < 25; i++ {
		if hBuf[i] == 0 {
			break
		}
	}

	Lprintf(4, "[INFO] request Body (%s) %d", hBuf[:], i)

	succ, result := Search(string(hBuf[:i])) //only search delete

	Lprintf(4, "[INFO] response Body (%s) ", result)

	sBuf := make([]byte, packetSize)
	if succ {
		copy(sBuf[:], result)
	} else {
		copy(sBuf[:], "999")
	}

	for bLen := 0; bLen < packetSize; {
		len, err := lcon.Write(sBuf[bLen:])
		if err != nil {
			Lprintf(1, "[FAIL] map service write fail(%s)", err)
			return
		}
		bLen = bLen + len
	}
	Lprintf(4, "[INFO] response Body write complete (%d) ", packetSize)
}

/*
func mapService(lcon net.Conn, connect bool) {

	headerSize := 8

	hBuf := make([]byte, headerSize)
	hLen, err := lcon.Read(hBuf)
	if err != nil {
		Lprintf(1, "[FAIL] map service header read fail(%s)", err)
		return
	}
	// read header at least
	for hLen < headerSize {
		len, err := lcon.Read(hBuf[hLen:])
		if err != nil {
			Lprintf(1, "[FAIL] map service header read fail(%s)", err)
			return
		}
		hLen = hLen + len
	}

	// check Packet length
	bodySize := binary.LittleEndian.Uint32(hBuf[4:hLen])
	Lprintf(4, "[INFO] service Body len (%d)", bodySize)

	// read body
	bBuf := make([]byte, bodySize)
	bLen, err := lcon.Read(bBuf)
	if err != nil {
		Lprintf(1, "[FAIL] map service header read fail(%s)", err)
		return
	}

	for uint32(bLen) < bodySize {
		len, err := lcon.Read(bBuf[bLen:])
		if err != nil {
			Lprintf(1, "[FAIL] map service header read fail(%s)", err)
			return
		}
		bLen = bLen + len
	}
	Lprintf(4, "[INFO] service Body (%v)", bBuf)
	Lprintf(4, "[INFO] service Body (%s)", bBuf[1:])

	// cmd 0: search, 1: search_delete, 2: insert, 3: insert force, 4, delete
	var result string
	var succ bool

	switch bBuf[0] {
	case 0:
		succ, result = Search(string(bBuf[1:]))
	case 1:
		succ, result = SearchDelete(string(bBuf[1:]))
	case 2:
		succ = Insert(string(bBuf[1:]))
	case 3:
		succ = InsertForce(string(bBuf[1:]))
	case 4:
		succ = Delete(string(bBuf[1:]))
	}

	bodySize = uint32(len(result) + 1)
	Lprintf(4, "[INFO] response Body (%s) - len(%d)", result, bodySize)

	sBuf := make([]byte, uint32(headerSize)+bodySize)
	sBuf[0] = hBuf[0]
	sBuf[1] = hBuf[1]
	sBuf[2] = hBuf[2]
	sBuf[3] = hBuf[3]

	binary.LittleEndian.PutUint32(sBuf[4:8], bodySize)
	if succ {
		sBuf[8] = 1
	}

	if bodySize > 1 {
		copy(sBuf[9:], result)
	}

	bLen = 0
	for bLen < len(sBuf) {
		len, err := lcon.Write(sBuf[bLen:])
		if err != nil {
			Lprintf(1, "[FAIL] map service write fail(%s)", err)
			return
		}
		bLen = bLen + len
	}
	Lprintf(4, "[INFO] response Body write complete (%d) - len(%d)", bLen, bodySize)
}
*/
