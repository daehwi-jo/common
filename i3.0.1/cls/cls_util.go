package cls

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os/exec"

	//	iconv "github.com/djimenez/iconv-go"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	gitnet "github.com/shirou/gopsutil/net"
)

var (
	Log      *log.Logger
	StatLog  *log.Logger
	fileStat *os.File
	deviceId int
	loglevel int
	logFile  string
	logTime  int
	logDate  int
	logWeek  = []string{".sun", ".mon", ".tue", ".wed", ".thr", ".fri", ".sat"}
)

func PrintPacket(recv []byte, len int) {
	fmt.Printf("recv packet len %d\n", len)
	for i := 0; i < len; i++ {
		fmt.Print(recv[i], " ")
	}
	fmt.Printf("\n")
}

func SetDeviceId(id int) {
	deviceId = id
}

func setLoglevel(level int) {
	loglevel = level
	log.SetFlags(log.LstdFlags)
}

func NewStat(binname string) {
	logStat := "/var/log/hydraplus.log"

	if len(binname) > 0 {
		println("StatFile: " + logStat)
	} else {
		fileStat.Close()
		backLogStat := fmt.Sprintf("%s-%d", logStat, logTime)
		os.Rename(logStat, backLogStat) // file backup
		Lprintf(4, "[INFO] rename(%s,%s) \n", logStat, backLogStat)

		cmd := "ls -lart /var/log/hydraplus.log-*"
		data, _ := exec.Command("bash", "-c", cmd).Output()
		fileList := strings.Split(strings.TrimSpace(string(data)), "\n")

		if len(fileList) > 6 {
			removeFile := strings.Split(fileList[0], " ")
			os.Remove(removeFile[len(removeFile)-1])
			Lprintf(4, "[INFO] fileList len(%d), remove(%s) \n", len(fileList), removeFile[len(removeFile)-1])
		}
	}

	logTime, _ = strconv.Atoi(time.Now().Format("20060102"))
	Lprintf(4, "[INFO] get logTime : %d \n", logTime)
	Lprintf(4, "[INFO] get logStat : %s \n", logStat)

	fileStat, err := os.OpenFile(logStat, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		Lprintf(1, "[ERROR] Stat File Open Error(%s) \n", err.Error())
	}

	StatLog = log.New(fileStat, "", log.LstdFlags) // |log.Lshortfile)

	//Lprints(1, "[start program (%s)]", binname)

}

func Lprints(level int, pre string, v ...interface{}) {
	if level <= loglevel {

		nTime, _ := strconv.Atoi(time.Now().Format("20060102"))
		if logTime != nTime {
			Lprintf(4, "[INFO] get nTime : %d, logTime : %d \n", nTime, logTime)
			NewStat("")
		}

		s := fmt.Sprintf(" [%d] : %s", deviceId, pre)

		if v == nil {
			StatLog.Print(s)
		} else {
			StatLog.Printf(s, v...)
		}
	}
}

func NewLog(logpath string) {
	var file *os.File
	var finfo os.FileInfo
	var err error

	logFile = logpath
	logDate = int(time.Now().Weekday())
	finfo, err = os.Stat(logFile + logWeek[logDate])
	if os.IsNotExist(err) || (err == nil && finfo.ModTime().Sub(time.Now()) > 24*time.Hour) {
		// file does not exist or 24 hour passed
		file, err = os.Create(logFile + logWeek[logDate])
		if err != nil {
			panic(err)
		}
		println("LogFile: " + logFile + logWeek[logDate])
	} else {
		// file exist
		file, err = os.OpenFile(logFile+logWeek[logDate], os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			panic(err)
		}
		println("LogFile: " + logFile + logWeek[logDate])
	}
	Log = log.New(file, "", log.LstdFlags) // |log.Lshortfile)
}

func NewWeek() {
	nDate := int(time.Now().Weekday())
	if logDate != nDate {
		logDate = nDate
		file, err := os.Create(logFile + logWeek[logDate])
		if err != nil {
			panic(err)
		}

		Log = log.New(file, "", log.LstdFlags) // |log.Lshortfile)
	}
}

func Lprintln(level int, pre string, v ...interface{}) {
	var s string
	if level <= loglevel {
		NewWeek()
		_, file, line, ok := runtime.Caller(1)
		if ok {
			//fName := runtime.FuncForPC(pc).Name()
			ret := strings.Split(file, "/")
			s = fmt.Sprintf(" %15s:%4d:  %s", ret[len(ret)-1], line, pre)
		} else {
			s = pre
		}

		if v == nil {
			Log.Println(s)
		} else {
			Log.Println(s, v)
		}
	}
}

func Lprintf(level int, pre string, v ...interface{}) {
	var s string
	if level <= loglevel {
		NewWeek()
		_, file, line, ok := runtime.Caller(1)
		if ok {
			//fName := runtime.FuncForPC(pc).Name()
			ret := strings.Split(file, "/")
			s = fmt.Sprintf(" %15s:%4d:  %s", ret[len(ret)-1], line, pre)
		} else {
			s = pre
		}

		if v == nil {
			Log.Print(s)
		} else {
			Log.Printf(s, v...)
		}
	}
}

func Lprint(level int, pre string, v ...interface{}) {
	var s string
	if level <= loglevel {
		NewWeek()
		_, file, line, ok := runtime.Caller(1)
		if ok {
			//fName := runtime.FuncForPC(pc).Name()
			ret := strings.Split(file, "/")
			s = fmt.Sprintf(" %15s:%4d:  %s", ret[len(ret)-1], line, pre)
		} else {
			s = pre
		}

		if v == nil {
			Log.Print(s)
		} else {
			Log.Print(s, v)
		}
	}
}

func LprintPacket(level int, recv []byte, l int) {
	var s string
	pre := fmt.Sprintf("[PACKET] len(%d):\n%v", l, recv[:l])

	if level <= loglevel {
		NewWeek()
		_, file, line, ok := runtime.Caller(1)
		if ok {
			//fName := runtime.FuncForPC(pc).Name()
			ret := strings.Split(file, "/")
			s = fmt.Sprintf(" %15s:%4d:  %s", ret[len(ret)-1], line, pre)
		} else {
			s = pre
		}
		Log.Print(s)
	}
}

func ShaEncode(orign []byte) string {
	hasher := sha1.New()
	hasher.Write(orign)
	// 이노지에스 코리아 암호화 방식 sha256 + base64
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	Lprintf(4, "[INFO] encoding result (%s)", sha)
	return sha
}

func GetTokenValue(t string, f string) (string, RESULT) {

	var i, s int

	file, err := os.Open(f)
	if err != nil {
		Lprintf(4, "[INFO] file did not exist (%s)", f)
		return f, CONF_NET
	}
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		Lprintf(1, "[FAIL] file read fail (%s)", f)
		return "ERR_READ", CONF_ERR
	}

	scanner := bufio.NewScanner(bytes.NewReader(DDecrypt(string(b))))
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			Lprintf(4, "[INFO] file read error (%s)", f)
			return "ERR_READ", CONF_ERR
		}

		c := scanner.Bytes()

		if len(c) == 0 {
			continue
		}

		for s = 0; s < len(c); s++ {
			if c[s] != ' ' || c[s] == '\n' || c[s] == '\r' {
				break
			}
		}

		if c[s] == '#' || c[s] == '\n' || c[s] == '\r' {
			continue
		}

		for i = s; i < len(c); i++ {
			if c[i] == ' ' || c[i] == '=' {
				break
			}
		}

		if t == string(c[s:i]) {
			for s = i; s < len(c); s++ {
				if c[s] != ' ' && c[s] != '=' {
					break
				}
			}
			for i = s; i < len(c); i++ {
				if c[i] == '#' || c[i] == '\r' || c[i] == '\n' {
					break
				}
			}

			// *.ini에 COD$_,7000,, 이런 형식으로 들어갈 경우 row 단위로 read 하다보니 복호화시 에러 발생으로 인한 로직 수정
			value := strings.Split(strings.TrimSpace(string(c[s:i])), ",")
			for i := 0; i < len(value); i++ {
				if strings.HasPrefix(value[i], "COD$_") {
					ipadr := value[i]
					bvalue := DDecrypt(ipadr[5:])
					value[i] = string(bvalue[:])
				}
				if i == 0 { // 중복값이 들어가므로 continue
					value[0] += fmt.Sprintf(",")
					continue
				}
				value[0] += fmt.Sprintf("%s,", value[i])
			}
			value[0] = strings.TrimRight(value[0], ",")

			return value[0], CONF_OK

			/*
			value := strings.TrimSpace(string(c[s:i]))
			if strings.HasPrefix(value, "COD$_") {
				bvalue := DDecrypt(value[5:])
				value = string(bvalue[:])
			}

			return value, CONF_OK
			*/
		}
	}

	return "", CONF_ERR
}

// config가 구분자로 값이 여러개 입력된 경우 사용 ex) &
func GetTokenValues(t string, f string, sep string) ([]string, RESULT) {

	var i, s int
	var values []string
	ErrMsg := []string{"ERR_READ"}

	file, err := os.Open(f)
	if err != nil {
		Lprintf(4, "[INFO] file read error (%s)\n", f)
		return ErrMsg, CONF_ERR
	}
	defer file.Close()

	b, err := ioutil.ReadAll(file)
	if err != nil {
		Lprintf(1, "[FAIL] file read fail (%s)", f)
		return ErrMsg, CONF_ERR
	}

	scanner := bufio.NewScanner(bytes.NewReader(DDecrypt(string(b))))
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			Lprintf(1, "[Err ] file read error (%s)\n", f)
			return ErrMsg, CONF_ERR
		}

		c := scanner.Bytes()

		if len(c) == 0 {
			continue
		}

		for s = 0; s < len(c); s++ {
			if c[s] != ' ' || c[s] == '\n' || c[s] == '\r' {
				break
			}
		}

		if c[s] == '#' || c[s] == '\n' || c[s] == '\r' {
			continue
		}

		for i = s; i < len(c); i++ {
			if c[i] == ' ' || c[i] == '=' {
				break
			}
		}

		if t == string(c[s:i]) {
			for s = i; s < len(c); s++ {
				if c[s] != ' ' && c[s] != '=' {
					break
				}
			}
			for i = s; i < len(c); i++ {
				if c[i] == '#' || c[i] == '\r' || c[i] == '\n' {
					break
				}
			}

			value := strings.TrimSpace(string(c[s:i])) // config value
			splitV := strings.Split(value, sep)

			if strings.HasPrefix(value, "COD$_") { // 암호화 된 경우
				bvalue := DDecrypt(value[5:])
				splitV = strings.Split(string(bvalue[:]), "&")
			}

			for _, v := range splitV { // split 후 여백이 있을 수 있으므로 trim
				values = append(values, strings.Trim(v, " "))
			}

			return values, CONF_OK
		}
	}

	return nil, CONF_ERR

}

// html util
func ParseHtml(packet []byte) ([]string, string, RESULT) {

	idx := bytes.Index(packet, []byte("\r\n\r\n"))

	if idx < 0 {
		return nil, "", CONF_ERR
	}

	head := string(packet[:idx+4])
	content := string(packet[idx+5:])

	headers := strings.Split(head, "\r\n")

	return headers, content, CONF_OK
}

func GetHeaderValue(headers []string, header string) (string, RESULT) {
	cnt := len(headers)

	for i := 0; i < cnt; i++ {
		row := headers[i]
		if strings.HasPrefix(row, header) {
			idx := strings.Index(row, ":")
			return strings.TrimSpace(row[idx+1:]), CONF_OK
		}
	}

	return "", CONF_ERR
}

// get header len content len
func GetHtmlLength(packet []byte) (int, int, RESULT) {

	idx := bytes.Index(packet, []byte("\r\n\r\n"))
	if idx < 0 {
		Lprintf(1, "[FAIL] can not receive whole http header (%s)\n", packet)
		return 0, 0, CONF_ERR
	}

	cds := bytes.Index(packet[:idx], []byte("Content-Length:"))
	if cds < 0 {
		Lprintf(1, "[FAIL] can not find Content-Length header (%s)\n", packet[:idx])
		return 0, 0, CONF_ERR
	}
	cde := bytes.Index(packet[cds:idx], []byte("\r\n"))
	if cde < 0 {
		Lprintf(1, "[FAIL] Content-Length header format is wrong (%s)\n", packet[cds:idx])
		return 0, 0, CONF_ERR
	}

	slen := strings.TrimSpace(string(packet[cds+16 : cds+cde]))
	clen, err := strconv.Atoi(slen)
	if err != nil {
		Lprintf(1, "[FAIL] Content-Length header format is wrong (%s)\n", slen)
		return 0, 0, CONF_ERR
	}

	return idx + 4, clen, CONF_OK
}

func get_eth_ip(eth string) string {
	var ipaddr string
	flag := 0

	interfStat, _ := gitnet.Interfaces()
	for _, interf := range interfStat {
		if interf.Name == eth {
			for _, addr := range interf.Addrs {
				ip := strings.Split(addr.Addr, "/")
				if strings.Contains(ip[0], ".") {
					ipaddr = ip[0]
					flag = 1
					break
				}
			}
			if flag == 1 {
				break
			}
		}
	}
	if flag == 1 {
		Lprintf(4, "[INFO] eth name:(%s), -ip:(%s)\n", eth, ipaddr)
		return ipaddr
	} else {
		Lprintf(4, "[INFO] eth name:(%s), -ip:(%s)\n", eth, ipaddr)
		return ""
	}
}

// decode utf8
//func GetUtf8(body []byte) {
//	charSet := []string{"utf-8", "euc-kr", "ksc5601", "iso-8859-1", "x-windows-949"}
//	for _, i := range charSet {
//		out, _ := iconv.ConvertString(string(body), i, "utf-8")
//		Lprintf(4, "[INFO] %s : %s \n", i, out)
//	}
//}
