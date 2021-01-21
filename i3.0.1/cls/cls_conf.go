package cls

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

var ConfDir string
var cls_Version string = "v----------^^^^^^^^^^----------v"
var Eth_card string

// get binary name
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

// get conf directory
func confDirString(args []string) string {
	length := len(args)
	var dir string

	for i := 2; i < length; i++ {
		// log 옵션이나 background mark 이면 추가 하지 않음
		if args[i] == "-L" || args[i] == "&" {
			break
		}

		if i == 2 {
			dir = fmt.Sprintf("%s", args[i])
		} else if i > 2 && args[i] != "-e" {
			dir += fmt.Sprintf("%s", args[i])
		} else {
			break
		}
	}

	return dir
}

func Cls_conf(args []string) string {
	var fname, logFname string
	var encFname string

	binName := runname(args[0])

	// args 3 개 이하인 경우
	if len(args) > 1 && args[1] == "-d" {
		ConfDir = confDirString(args)
		fmt.Printf("[INFO] ConfDir : [%s]\n", ConfDir)

		fname = fmt.Sprintf("%s/conf/%s.ini", ConfDir, binName)
		logFname = fmt.Sprintf("%s/log/%sLOG", ConfDir, binName)

		encFname = fmt.Sprintf("%s/conf/%s.inc", ConfDir, binName)

		if _, err := os.Stat(fname); !os.IsNotExist(err) { // file exists
			src, _ := ioutil.ReadFile(fname)
			ioutil.WriteFile(encFname, []byte(EEncode(src)), 0644)

			v, r := GetTokenValue("CONF_DEL", encFname)
			if r != CONF_ERR && v == "1" {
				Lprintf(4, "[INFO] DEL CONF (%s)", v)
				os.Remove(fname)
			}
		}
		fname = encFname

	} else if len(args) > 1 && args[1] == "-v" {
		fmt.Printf("[INFO] %s verison is %s\n", binName, cls_Version)
		os.Exit(0)
	} else {
		fmt.Println("[FAIL] -d [path] : 데몬 기동 path - 데몬 경로 입력")
		os.Exit(0)
	}

	// set log level
	if len(args) > 3 && (args[3] == "-L" || args[3] == "-l") {
		level, err := strconv.Atoi(strings.TrimSpace(args[4]))
		if err != nil {
			fmt.Printf("[ERR ] level setting error : %s\n", err)
			return fname
		}
		setLoglevel(level)
	} else {
		setLoglevel(4) // default log level
	}

	// set ethernet card
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
	}

	NewLog(logFname)

	return fname
}
