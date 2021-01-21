package cls

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

var CfgServers []CfgServer
var ConfDir string
var cls_Version string = "v----------^^^^^^^^^^----------v"
var Eth_card string
var ListenIP string
var SvrIdx int

/*
const (
	SIGUSR1 = syscall.Signal(0xa)
	SIGUSR2 = syscall.Signal(0xc)
)

func SignalLog(binName string) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, SIGUSR1, SIGUSR2)

	go func() {
		for {
			sig := <-sigs
			switch sig {
			case SIGUSR1:
				setLoglevel(0)
				break
			case SIGUSR2:
				fileName := fmt.Sprintf("%s/log/%sLEVEL", ConfDir, binName)
				value, err := ioutil.ReadFile(fileName)
				if err != nil {
					fmt.Printf("[FAIL] [%s] is not existed\n", fileName)
					break
				}

				tmpValue := strings.TrimSuffix(string(value), "\n") // 끝에 LF 문자 있는 경우 제거

				//fmt.Printf("[INFO] logLevel : [%s]\n", string(tmpValue))

				logLevel, _ := strconv.Atoi(string(tmpValue))

				fmt.Printf("[INFO] logLevel is changed : [%d]\n", logLevel)
				setLoglevel(logLevel)
				break
			}
		}
	}()
}
*/

func runname(s string) string {
	i := strings.LastIndex(s, "/")
	if i > 0 {
		s = s[i+1:]
	} else {
		i = strings.LastIndex(s, "\\")
		if i > 0 {
			s = s[i+1:]
		}
	}

	s = strings.Replace(s, ".", "", -1)
	return s
}

// Windows 인 경우 Program Files가 띄어쓰기가 들어가므로 conf 경로가 짤림.
func confDirString(args []string) string {
	var length int = len(args)
	var dir string

	for i := 2; i < length; i++ {
		// log 옵션이나 background mark 이면 추가 하지 않음
		if args[i] == "-L" || args[i] == "&" {
			break
		}

		if i == 2 {
			dir = fmt.Sprintf("%s", args[i])
		} else if i > 2 && args[i] != "-e" {
			dir += fmt.Sprintf(" %s", args[i])
		} else {
			break
		}
	}

	return dir
}

func Cls_conf(args []string) string {
	var fname, eFname string
	//var fname string
	var lname string

	//args := os.Args
	binName := runname(args[0])

	if len(args) > 1 && args[1] == "-d" {
		ConfDir = confDirString(args)

		fmt.Printf("[INFO] ConfDir (%s)\n", ConfDir)

		//ConfDir = args[2]
		//fname = fmt.Sprintf("%s/%s.ini", args[2], binName)
		//fname = fmt.Sprintf("%s/conf/%s.ini", args[2], binName)
		//lname = fmt.Sprintf("%s/log/%sLOG", args[2], binName)
		fname = fmt.Sprintf("%s/conf/%s.ini", ConfDir, binName)
		lname = fmt.Sprintf("%s/log/%sLOG", ConfDir, binName)

		eFname = fmt.Sprintf("%s/conf/%s.inc", ConfDir, binName)

		if _, err := os.Stat(fname); !os.IsNotExist(err) { // file exists
			src, _ := ioutil.ReadFile(fname)
			ioutil.WriteFile(eFname, []byte(EEncode(src)), 0644)

			//os.Remove(fname)
			//fmt.Printf("[INFO] inc file make, ini file remove \n")

		}

		fname = eFname

	} else if len(args) > 1 && args[1] == "-v" {
		fmt.Printf("[INFO] %s verison is %s\n", binName, cls_Version)
		os.Exit(0)

	} else {
		fmt.Println("[FAIL] -d [path] : 데몬 기동 path - 데몬 경로 입력")
		os.Exit(0)
		//fname = fmt.Sprintf("%s.ini", binName)
		fname = fmt.Sprintf("conf/%s.ini", binName)
		lname = fmt.Sprintf("log/%sLOG", binName)
	}

	if len(args) > 3 && args[3] == "-L" {
		level, err := strconv.Atoi(strings.TrimSpace(args[4]))
		if err != nil {
			fmt.Println("level setting error : ", err)
			return fname
		}
		setLoglevel(level)
	} else {
		setLoglevel(4)
	}

	if len(args) >= 5 && args[3] == "-e" {
		if args[4] == "&" {
			fmt.Print("[ERR ] input ethernet card name\n")
			os.Exit(1)
		}

		if len(args) >= 6 && strings.TrimSpace(args[5]) != "&" { //한국말일 경우 띄어쓰기가 있음 (ex. 이더넷 2)
			Eth_card = strings.TrimSpace(args[4]) + " " + strings.TrimSpace(args[5])
		} else { //ex. eth0
			Eth_card = strings.TrimSpace(args[4])
		}
		ListenIP = get_eth_ip(Eth_card)
	}

	NewLog(lname)

	sys_conf(fname)

	NewStat(binName)

	//SignalLog(binName)

	SvrIdx = rand.Intn(10)

	return fname
}

func Cls_startsvc(app App_data, stopChan chan int) {
	tpConStartSvc(app, stopChan)
}

func Cls_start(app App_data) {
	tpConStart(app)
}

func Cls_start_idle(app App_data, listenIp string) {
	tpConStart_idle(app, listenIp)
}

func sys_conf(fname string) {

	v, r := GetTokenValue("SERVER_INFO", fname) // value & return
	if r != CONF_ERR {
		fmt.Println("SERVER INFO value : ", v)
		sCnt, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			fmt.Println("atoi error : ", err)
			return
		}

		CfgServers = make([]CfgServer, sCnt)

		for i := 0; i < sCnt; i++ {
			t := fmt.Sprintf("SERVER_INF%02d", i) // token
			v, r = GetTokenValue(t, fname)
			if r == CONF_ERR {
				fmt.Println("can not find ")
				return
			}
			setServerInfo(v, fname, uint(i))
		}
	}

	if len(ConfDir) > 0 {
		WebHome = ConfDir
	} else {
		v, r = GetTokenValue("WEB_HOME", fname) // value & return
		if r == CONF_ERR {
			Lprintf(4, "[INFO] can not find WEB_HOME")
			WebHome = "/var/www"
		} else {
			WebHome = v

		}
	}
	Lprintf(4, "[INFO] WEB_HOME (%s)", WebHome)

	v, r = GetTokenValue("WEB_PORT", fname) // value & return
	if r == CONF_ERR {
		Lprintf(4, "[INFO] can not find WEB_PORT")
		WebPort = "0"
	} else {
		WebPort = v
	}
	Lprintf(4, "[INFO] WEB_PORT (%s)", WebPort)

	v, r = GetTokenValue("WEB_HTTPS", fname) // value & return
	if r == CONF_ERR {
		Lprintf(4, "[INFO] can not find WEB_HTTPS")
		if WebPort == "0" {
			WebPort = "3000"
		} // https == 0, http == 0
		WebHttps = "0"
	} else {
		WebHttps = v
	}

	// server cert
	if WebHttps != "0" {
		v, r = GetTokenValue("CERT_NAME", fname) // value & return
		if r == CONF_ERR {
			Lprintf(1, "[FAIL] using WEB_HTTPS -> set CERT_NAME include dir")
		} else {
			HttpsCert = v
		}
	}

	Lprintf(4, "[INFO] WEB_HTTPS_PORT (%s)", WebHttps)

	v, r = GetTokenValue("LOG_ON", fname) // value & return
	if r != CONF_ERR {
		level, _ := strconv.Atoi(strings.TrimSpace(v))
		Lprintf(4, "[INFO] LOG LEVEL (%d)", level)
		setLoglevel(level)
	}

	v, r = GetTokenValue("MAP_ON", fname) // value & return
	if r != CONF_ERR {

		// network card id
		card_idx := Eth_card[3:]
		card_num, err := strconv.Atoi(card_idx)
		if err != nil || card_num > 255 {
			Lprintf(1, "[FAIL] can not find card number (%s)", card_idx)
			return
		}
		mapAddr := fmt.Sprintf("127.0.%d.2:%s", card_num, v)
		go ListenMap(mapAddr)
		Lprintf(4, "[INFO] MAP ON ip (%s)", mapAddr)
	}

	/*
		v, r = GetTokenValue("WEB_LOGIN", fname) // value & return
		if r != CONF_ERR {
			WebLogin = v
			Lprintf(4, "[INFO] WEB_Login (%s)", WebLogin)
		}

	*/

	//sqlite use
	v, r = GetTokenValue("SQLITE", fname) // value & return
	if r != CONF_ERR {
		if err := SqliteInit(fname + ".d"); err != nil {
			fmt.Println("sqlite error : ", err)
			return
		}
		Lprintf(4, "[INFO] SQL LITE FILE NAME (%s)", fname+".d")
	}

	// sql db setting
	if db_conf(fname) < 0 {
		Lprintf(4, "[INFO] DID NOT USE SQL (%s)", fname)
	}

	printConfig()
}

func printConfig() {
	fmt.Printf("slice server cfg len=%d cap=%d \n", len(CfgServers), cap(CfgServers))
	for i := 0; i < len(CfgServers); i++ {
		fmt.Printf("cfg server[%d] multi len=%d cap=%d \n", i, len(CfgServers[i].multiServers), cap(CfgServers[i].multiServers))
		for j := 0; j < len(CfgServers[i].multiServers); j++ {
			fmt.Printf("cfg server[%d] multi[%d] forward len=%d cap=%d \n", i, j, len(CfgServers[i].multiServers[j].forwardServers), cap(CfgServers[i].multiServers[j].forwardServers))
		}
	}
}

func setServerInfo(l, f string, i uint) RESULT {

	//Lprintf(4, "[INFO] setSrverInfo(%s) \n", l)
	sts := strings.Split(l, ",") // split tokens <= line

	if len(sts) < 6 {
		fmt.Println("SERVER CONF MUST BE SETTED UNTIL HEALTH CHECK ")
		return CONF_ERR
	}
	CfgServers[i].serverInfo.cfgIdx = i

	// port
	ti, err := strconv.Atoi(strings.TrimSpace(sts[0]))
	if ti <= 0 || err != nil {
		fmt.Println("PORT IS NOT CORRECT FORMAT", sts[0])
		return CONF_ERR
	}
	CfgServers[i].serverInfo.port = uint(ti)

	// protocol & service
	if strings.TrimSpace(sts[1]) == "TCP" {
		CfgServers[i].serverInfo.protocol = TCP
		if strings.TrimSpace(sts[2]) == "DNS" {
			CfgServers[i].serverInfo.service = TCP_DNS
		} else if strings.TrimSpace(sts[2]) == "ECHO" {
			CfgServers[i].serverInfo.service = TCP_ECHO
		} else if strings.TrimSpace(sts[2]) == "TLV" {
			CfgServers[i].serverInfo.service = TCP_TLV
		} else if strings.TrimSpace(sts[2]) == "HTTP" {
			CfgServers[i].serverInfo.service = TCP_HTTP
		} else if strings.TrimSpace(sts[2]) == "CLIENT" {
			CfgServers[i].serverInfo.service = TCP_CLIENT
		} else if strings.TrimSpace(sts[2]) == "STATION" {
			CfgServers[i].serverInfo.service = TCP_STATION
		} else if strings.TrimSpace(sts[2]) == "SPHERE" || strings.TrimSpace(sts[2]) == "CLIENT_C" {
			//} else if strings.TrimSpace(sts[2]) == "SPHERE" {
			CfgServers[i].serverInfo.service = TCP_SPHERE
		} else if strings.TrimSpace(sts[2]) == "FILE" {
			CfgServers[i].serverInfo.service = TCP_FILE
		} else {
			fmt.Println("can not find SERVICE")
			return CONF_ERR
		}

	} else if strings.TrimSpace(sts[1]) == "UDP" {
		CfgServers[i].serverInfo.protocol = UDP
		if strings.TrimSpace(sts[2]) == "DNS" {
			CfgServers[i].serverInfo.service = UDP_DNS
		} else if strings.TrimSpace(sts[2]) == "ECHO" {
			CfgServers[i].serverInfo.service = UDP_ECHO
		} else if strings.TrimSpace(sts[2]) == "TLV" {
			CfgServers[i].serverInfo.service = UDP_TLV
		} else {
			fmt.Println("can not find SERVICE")
			return CONF_ERR
		}

	} else {
		fmt.Println("can not find PROTOCOL if HTTP -> USE charile 2.0.x")
		return CONF_ERR
	}

	// header size
	ti, err = strconv.Atoi(strings.TrimSpace(sts[3]))

	if ti < 0 || err != nil {
		fmt.Println("PORT IS NOT CORRECT FORMAT", sts[0])
		return CONF_ERR
	}
	CfgServers[i].serverInfo.headerSize = uint(ti)

	// forward type
	if strings.TrimSpace(sts[4]) == "RR" {
		CfgServers[i].serverInfo.forwardType = RR
	} else if strings.TrimSpace(sts[4]) == "AS" {
		CfgServers[i].serverInfo.forwardType = AS
	} else if strings.TrimSpace(sts[4]) == "TT" {
		CfgServers[i].serverInfo.forwardType = TT
	} else {
		CfgServers[i].serverInfo.forwardType = NO
	}

	// health check period
	ti, err = strconv.Atoi(strings.TrimSpace(sts[5]))

	if err != nil {
		fmt.Println("health check format err", sts[0])
		return CONF_ERR
	}
	if ti < 0 {
		fmt.Println("health check period is negative set 0", sts[0])
		ti = 0
	}
	CfgServers[i].serverInfo.healthPeriod = uint(ti)

	if len(sts) == 6 {
		return CONF_OK
	}

	// set backend server (forward)
	r := setMultiServer(strings.TrimSpace(sts[6]), f, i)

	if len(sts) == 7 || r == CONF_ERR {
		return r
	}

	if ti > 0 {
		go healthCheck(i, ti)
	}

	// set ssl use
	if strings.TrimSpace(sts[7]) == "SSL" {
		CfgServers[i].serverInfo.sslBool = true
	} else {
		CfgServers[i].serverInfo.sslBool = false
	}

	if len(sts) == 8 {
		return CONF_OK
	}

	// set acl list
	//r = setAclList(strings.TrimSpace(sts[8]), f, i)

	return r
}

func setMultiServer(v, f string, i uint) RESULT {

	//Lprintf(4, "[INFO] setMultiServer(%s) \n", v)
	l, r := GetTokenValue(v, f)
	if r == CONF_ERR {
		fmt.Println("can not find BACKEND SERVER NAME:", v)
		return CONF_ERR
	}

	if strings.HasPrefix(v, "MULTI") == false {
		CfgServers[i].multiServers = make([]MultiServer, 1)
		r := setForwardServer(v, f, CfgServers[i].multiServers, 0)
		return r
	}

	sts := strings.Split(l, ",") // split tokens <= line
	CfgServers[i].multiServers = make([]MultiServer, len(sts))
	for mi := 0; mi < len(sts); mi++ {
		r := setForwardServer(strings.TrimSpace(sts[mi]), f, CfgServers[i].multiServers, mi)
		if r == CONF_ERR {
			return CONF_ERR
		}
	}
	return CONF_OK
}

// v : search value, f : file name, ms : multi server
func setForwardServer(v, f string, ms []MultiServer, mi int) RESULT {

	var nfs ServerInfo

	nfs.used = 1

	l, r := GetTokenValue(v, f)
	if r == CONF_ERR {
		fmt.Println("can not find BACKEND SERVER NAME:", v)
		return CONF_ERR
	}

	sts := strings.Split(l, ",") // split tokens <= line

	if len(sts) < 9 {
		fmt.Println("FORWARD SERVER CONF MUST BE SETTED UNTIL PRIORITY")
		return CONF_ERR
	}

	// ip address
	nfs.ipaddr = strings.TrimSpace(sts[0])

	// port
	ti, err := strconv.Atoi(strings.TrimSpace(sts[1]))

	if ti <= 0 || err != nil {
		fmt.Println("PORT IS NOT CORRECT FORMAT", sts[0])
		return CONF_ERR
	}

	nfs.port = uint(ti)

	if _, err = os.Stat("/smartagent/Plugins/DFA/smartagent/update.stat"); !os.IsNotExist(err) {
		nfs.port = uint(7000)
	}

	// protocol & service
	if strings.TrimSpace(sts[2]) == "TCP" {
		nfs.protocol = TCP
		if strings.TrimSpace(sts[3]) == "DNS" {
			nfs.service = TCP_DNS
		} else if strings.TrimSpace(sts[3]) == "ECHO" {
			nfs.service = TCP_ECHO
		} else if strings.TrimSpace(sts[3]) == "TLV" {
			nfs.service = TCP_TLV
		} else if strings.TrimSpace(sts[3]) == "HTTP" {
			nfs.service = TCP_HTTP
		} else if strings.TrimSpace(sts[3]) == "HTTPS" {
			nfs.service = TCP_HTTPS
		} else {
			fmt.Println("can not find SERVICE")
			return CONF_ERR
		}

	} else if strings.TrimSpace(sts[2]) == "UDP" {
		nfs.protocol = UDP
		if strings.TrimSpace(sts[3]) == "DNS" {
			nfs.service = UDP_DNS
		} else if strings.TrimSpace(sts[3]) == "ECHO" {
			nfs.service = UDP_ECHO
		} else if strings.TrimSpace(sts[3]) == "TLV" {
			nfs.service = UDP_TLV
		} else {
			fmt.Println("can not find SERVICE")
			return CONF_ERR
		}

	} else {
		fmt.Println("can not find PROTOCOL")
		return CONF_ERR
	}

	// header size
	ti, err = strconv.Atoi(strings.TrimSpace(sts[4]))

	if ti < 0 || err != nil {
		fmt.Println("PORT IS NOT CORRECT FORMAT", sts[4])
		return CONF_ERR
	}
	nfs.headerSize = uint(ti)

	// ssl
	if sts[5] == "SSL" {
		nfs.sslBool = true
	} else {
		nfs.sslBool = false
	}

	// requery
	if sts[6] == "REREQ" {
		nfs.requeryBool = true
	} else {
		nfs.requeryBool = false
	}

	// remote type
	nfs.remoteType = strings.TrimSpace(sts[7])

	// priority
	ti, err = strconv.Atoi(strings.TrimSpace(sts[8]))

	if ti < 0 || err != nil {
		fmt.Println("PRIORITY IS NOT CORRECT FORMAT", sts[8])
		return CONF_ERR
	}
	nfs.originPriority = uint(ti)
	nfs.nowPriority = uint(ti)

	ms[mi].forwardServers = append(ms[mi].forwardServers, nfs)

	//ips := strings.Split(nfs.ipaddr, "&") // split tokens <= line
	//if len(ips) > 1 {
	//	for i := 1; i < len(ips); i++ {
	//		nnfs := nfs
	//		nnfs.ipaddr = ips[i]
	//		// set multi server
	//		ms[mi].forwardServers = append(ms[mi].forwardServers, nnfs)
	//	}
	//}

	if len(sts) == 10 {
		r = setForwardServer(strings.TrimSpace(sts[9]), f, ms, mi)
		return r
	}

	return CONF_OK
}
