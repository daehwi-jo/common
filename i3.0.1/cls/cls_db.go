package cls

import (
	"context"
	"database/sql"
	"encoding/json"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"

	// "github.com/go-sql-driver/mysql"

	"github.com/go-sql-driver/mysql-1.5.0"

	_ "github.com/denisenkom/go-mssqldb"
	//_"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql-1.5.0"
)

var Dbbd string   // dbms name - mssql, mysql
var Dbid string   // dbms id
var Dbps string   // dbms password
var Dbpt string   // dbms port
var Dbnm string   // dbms instance
var Dbssl int     // dbms ssl encrypt option
var DbTimeOut int // dbms timeout
var DBAgentPort string

var DBc *sql.DB
var DBRand *rand.Rand
var ConnIdx int     // 현재 접속중인 ip 배열 index - 최초는 0번째 ip로 연결
var ConnLen int     // 접속할 ip 갯수
var Dbip []string   // dbms ip
var DbipList string // dbms ip list

var DBMutex sync.RWMutex

//유효성 메세지 저장 메모리
var validationMap = struct {
	sync.RWMutex
	data map[string]MessageValue
}{data: make(map[string]MessageValue)}

func SetInternelValidationMap(Arry []MessageArray) {

	for i := 0; i < len(Arry); i++ {
		Lprintf(4, "[INFO] Validation Key : [%s]\n", Arry[i].VKey)
		Lprintf(4, "[INFO] Validation Value : [%s]\n", Arry[i].MsgArray)
		SetValidationMap(Arry[i].VKey, Arry[i].MsgArray)
	}
}

func SetValidationMap(vKey string, value MessageValue) {
	validationMap.Lock()
	validationMap.data[vKey] = value
	validationMap.Unlock()
}

func GetValidationMap(Vkey string) (MessageValue, bool) {
	validationMap.RLock()
	vInfo, ok := validationMap.data[Vkey]
	validationMap.RUnlock()

	return vInfo, ok
}

type MessageValue struct {
	MessageType string `json:"mtype"`
	Kr          string `json:"kr"`
	En          string `json:"en"`
	Cn          string `json:"cn"`
}

type MessageArray struct {
	VKey     string       `json:"key"`
	MsgArray MessageValue `json:"msgArray"`
}

// BaseAPI Validation Response struct
type RespValidation struct {
	Code        string       `json:"code"`
	Message     MessageValue `json:"message"`
	ServiceName string       `json:"serviceName"`

	MsgArray []MessageArray `json:"msgArray"`
}

// resut for more viewing
type RespDbms struct {
	Result   int
	EventYn  string
	RowCount int
}

// database error
type DbErr struct {
	Level   string
	Code    int
	Message string
}

const (
	DBCONN_ERR     = 1 // db 접속 변경
	DBCONN_CONTI       // db 접속 유지
	DBCONN_DECLINE     // db 응답 느림
	DBETC_ERR          // 이 외의 에러인 경우
)

// base API에서 유효성 메세지 가져오기
func GetValidationData(url string) bool {
	var requestURL string
	var respData RespValidation
	requestURL = url + "/v1/base/validation"

	req, err := http.NewRequest("POST", requestURL, nil)
	if err != nil {
		Lprintf(1, "[ERR ] http new requset err(%s) \n", err.Error())
		return false
	}

	req.Header.Add("Content-Type", "application/json")

	// send
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		Lprintf(1, "[ERR ] client.Do : [%s]\n", err)
		return false
	}

	// check response
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		Lprintf(1, "[ERR ] ioutil.ReadAll : [%s]\n", err)
		resp.Body.Close()
		return false
	}
	resp.Body.Close()
	//Lprintf(4, "[INFO] API CALL Response Body : [%s]\n", respBody)

	if err := json.Unmarshal(respBody, &respData); err != nil {
		Lprintf(1, "[ERR ] json.Unmarshal : [%s]\n", err)
		return false
	}

	//Lprintf(4, "[INFO] apiCallResponse : [%v]\n", respData)
	if respData.Code != "0000" {
		Lprintf(1, "[ERR ] api call response code : [%s]\n", respData.Code)
		return false
	}

	if len(respData.MsgArray) == 0 {
		Lprintf(1, "[ERR ] Validation Message NULL POINT \n")
		return false
	} else {
		for i := 0; i < len(respData.MsgArray); i++ {
			SetValidationMap(respData.MsgArray[i].VKey, respData.MsgArray[i].MsgArray)
		}
	}

	return true

}

func Db_conf(fname string) int {
	Lprintf(4, "[INFO] conf start (%s)\n", fname)

	// dbms connect address
	DBMutex.Lock()
	defer DBMutex.Unlock()

	dbip, r := GetTokenValue("HOST_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS not exist value\n")
		return (-1)
	}
	Lprintf(4, "[INFO] Dbip : (%v)\n", dbip)
	DbipList = dbip
	Dbip = strings.Split(dbip, "&")
	ConnLen = len(Dbip)

	s1 := rand.NewSource(time.Now().UnixNano())
	DBRand = rand.New(s1)
	ConnIdx = DBRand.Intn(ConnLen)

	// dbms connect id
	dbid, r := GetTokenValue("ID_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_ID not exist value\n")
		return (-1)
	}
	Dbid = dbid
	Lprintf(4, "[INFO] Dbid : (%s)\n", Dbid)

	// dbms connect password
	dbps, r := GetTokenValue("PASSWD_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_PASS not exist value\n")
		return (-1)
	}
	Dbps = dbps
	Lprintf(4, "[INFO] Dbps : (%s)\n", Dbps)

	// dbms instance name
	dbnm, r := GetTokenValue("NAME_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_DB not exist value\n")
		return (-1)
	}
	Dbnm = dbnm
	Lprintf(4, "[INFO] Dbnm : (%s)\n", Dbnm)

	// dbms instance name
	dbpt, r := GetTokenValue("PORT_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_DB not exist value\n")
		return (-1)
	}
	Dbpt = dbpt
	Lprintf(4, "[INFO] Dbpt : (%s)\n", Dbpt)

	// dbms brand
	dbbd, r := GetTokenValue("DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_DB not exist value\n")
		dbbd = "mysql"
	}
	Dbbd = dbbd
	Lprintf(4, "[INFO] Dbbd : (%s)\n", Dbbd)

	dbssl, r := GetTokenValue("SSL_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] SSL_DBMS not exist value\n")
	}

	if dbssl == "Y" {
		Dbssl = 1
		Lprintf(4, "[INFO] DBMS SSL ENCRYPT USE \n")
	}

	// dbms timeout
	dbTimeout, r := GetTokenValue("TIMEOUT_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] TIMEOUT_DBMS not exist value, so set 10 seconds\n")
		dbTimeout = "10" // db query timeout config에 미설정시 default 값으로 10초 설정
		//return (-1)
	}
	DbTimeOut, _ = strconv.Atoi(dbTimeout)
	Lprintf(4, "[INFO] DbTimeOut : %d\n", DbTimeOut)

	DBc, _ = Initdb(dbbd, dbid, dbps, Dbip[ConnIdx], dbpt, dbnm)

	if DBc == nil {
		return (-1)
	}

	//go CheckDbmsLive()

	return 0
}

func Initdb(dbbd, dbid, dbps, dbip, dbpt, dbnm string) (*sql.DB, error) {
	Lprintf(4, "[INFO] new db connection try %s \n", dbip)

	var c *sql.DB
	var err error

	if dbbd == "mssql" {
		c, err = sql.Open("mssql", "server="+dbip+";user id="+dbid+";password="+dbps+";port="+dbpt+";database="+dbnm)
		if err != nil {
			Lprintf(1, "[FAIL] db connection error")
			return nil, err
		}
	} else {

		if Dbssl == 1 {

			/*
				ssl_ca (인증기관 인증서) : /smartagent/Plugins/DFA/ssl/ca-cert.pem
				ssl_cert (public key) : /smartagent/Plugins/DFA/ssl/ca-cert.pem
				ssl_key (private key) : /smartagent/Plugins/DFA/ssl/server-pkey.pem
			*/

			sslKeyPath := fmt.Sprintf("%s/ca-cert.pem", ConfDir)
			Lprintf(4, "[INFO] sslKeyPath (%s)\n", sslKeyPath)

			rootCertPool := x509.NewCertPool()
			pem, err := ioutil.ReadFile(sslKeyPath)
			if err != nil {
				Lprintf(1, "[FAIL] ssl error (%s)\n", err.Error())
			}

			if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
				Lprintf(1, "[FAIL] Failed to append PEM \n")
			}

			mysql.RegisterTLSConfig("custom", &tls.Config{
				RootCAs:            rootCertPool,
				InsecureSkipVerify: true,
			})

			c, err = sql.Open("mysql", dbid+":"+dbps+"@tcp("+dbip+":"+dbpt+")/"+dbnm+"?tls=custom")
			if err != nil {
				Lprintf(1, "[FAIL] db connection error")
				return nil, err
			}

		} else {
			c, err = sql.Open("mysql", dbid+":"+dbps+"@tcp("+dbip+":"+dbpt+")/"+dbnm)
			if err != nil {
				Lprintf(1, "[FAIL] db connection error")
				return nil, err
			}
		}

	}

	// c.SetMaxIdleConns(10)
	// c.SetMaxOpenConns(100)

	// Due to connect db, it required setting.
	// dbms max_connections 수에 맞게 설정 변경 필요
	c.SetConnMaxLifetime(time.Minute * 3)
	c.SetMaxIdleConns(0)  // 재사용 connection 수
	c.SetMaxOpenConns(20) // 최대 커넥션 수

	return c, nil
}

// db에 재 접속한다.
func DbmsReinit() {

	newIdx := DBRand.Intn(ConnLen)
	Lprintf(4, "[INFO] DBMS connection change next (%d) \n", newIdx)
	if err := DBc.Close(); err != nil { // 기존 DB CLOSE
		Lprintf(1, "[ERR ] DBc close is error : [%s]\n", err)
		return
	}

	c, err := Initdb(Dbbd, Dbid, Dbps, Dbip[newIdx], Dbpt, Dbnm)
	if err != nil {
		Lprintf(1, "[ERR ] DBc init error : [%s]\n", err)
		return
	}
	DBc = c
	ConnIdx = newIdx
	return
}

// config에 등록된 다른 DBMS로 연결한다.
func DbmsDuplexing() {
	Lprintf(4, "[INFO] DBMS connection change now (%s) ---> next \n", Dbip[ConnIdx])
	if err := DBc.Close(); err != nil { // 기존 DB CLOSE
		Lprintf(1, "[ERR ] DBc close is error : [%s]\n", err)
	}

	newIdx := (ConnIdx + 1) % ConnLen
	c, err := Initdb(Dbbd, Dbid, Dbps, Dbip[newIdx], Dbpt, Dbnm)
	DBc = c
	if err == nil {
		ConnIdx = newIdx
	}
	return
}

// dbms iplist change
func ChangeDBMS(iplist string) bool {
	if iplist == DbipList {
		return false
	}

	DBMutex.Lock()
	Dbip = strings.Split(iplist, "&")
	ConnLen = len(Dbip)
	DbmsReinit()
	DBMutex.Unlock()

	return true
}

// DBMS 헬스체크 - 30 초에 한번
func CheckDbmsLive() {
	Lprintf(4, "[INFO] check db connection start \n")
	fctl := "/smartagent/Plugins/DFA/smartagent/tmp/scale.ctl"
	fname := "/smartagent/Plugins/DFA/smartagent/tmp/scale.data"
	for {
		time.Sleep(30 * time.Second) // change sleep time 10 to 30
		err := DBc.Ping()

		if err != nil {
			Lprintf(4, "[INFO] check db ping error (%s)\n", err)

			DBMutex.Lock()
			DbmsDuplexing()
			DBMutex.Unlock()
		}

		// db ip check
		if _, err := os.Stat(fctl); os.IsNotExist(err) {
			continue
		}
		os.Remove(fctl)
		v, r := GetTokenValue("DBIP", fname) // value & return
		Lprintf(1, "[INFO] DB change value : %s \n", v)
		if r != CONF_ERR {
			ChangeDBMS(v)
		}
		os.Remove(fname)
	}
}

// DBMS retry 기능이 들어간 쿼리
func QueryDB(query string) (*sql.Rows, error) {
	if DBc == nil {
		time.Sleep(10 * time.Millisecond)
	}

	DBMutex.RLock()
	rows, err := DBc.Query(query)
	DBMutex.RUnlock()

	//Lprintf(4, "[INFO] query resp string : %s\n", err)
	if err != nil {
		Lprintf(1, "[ERR ] Query error : %s \n", err)
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no route to host") {
			DbmsDuplexing()
		}
		// try one more
		DBMutex.RLock()
		defer DBMutex.RUnlock()
		return DBc.Query(query)
	}
	return rows, err
}

// DBMS Timeout 기능이 들어간 쿼리
// cancel() - Canceling this context releases resources associated with it, so code should call cancel as soon as the operations running in this Context complete
func QueryTimeOut(query string) (*sql.Rows, uint, context.CancelFunc) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(DbTimeOut))
	rows, err := DBc.QueryContext(ctx, query)

	//Lprintf(4, "[INFO] query resp string : %s\n", err)
	if err != nil {
		Lprintf(1, "[ERR ] QueryContext : %s \n", err)

		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no route to host") {
			// 서버 접속이 안됨으로 판단하고 DB Session 교체
			DbmsDuplexing()
			Lprintf(4, "[INFO] DBMS down, so changed\n")
			return nil, DBCONN_ERR, cancel

		} else if strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "connection timed out") {
			//err = DBc.ping()
			//if err != nil {
			DbmsDuplexing()
			Lprintf(4, "[INFO] DBMS down(%s), so changed\n", err.Error())
			return nil, DBCONN_ERR, cancel
			//}
			//	Lprintf(4, "[INFO] DBMS live, but response is slow so not changed\n")
			//	return nil, DBCONN_DECLINE, cancel

		} else {
			Lprintf(1, "[ERR ] query error : %s\n", err)
			return nil, DBETC_ERR, cancel
		}
	}
	//defer cancel() // releases resources if slowOperation completes before timeout elapses

	return rows, 0, cancel
}

// DBMS Transaction 쿼리
// insert, update, delete 쿼리 또는 프로시져인 경우 tx.Rollback(), tx.Commit() 호출 필수
// select 또는 resultSet이 return되는 프로시져인 경우 rows.Close() 호출 필수
func TxQueryDB(query string) (*sql.Tx, *sql.Rows, error) {
	if DBc == nil {
		time.Sleep(10 * time.Millisecond)
	}

	tx, err := DBc.Begin()
	if err != nil {
		Lprintf(1, "[ERR ] Begin : %s\n", err)
		return tx, nil, err
	}

	rows, err := tx.Query(query)
	if err != nil {
		Lprintf(1, "[ERR ] Query : %s\n", err)
		return tx, rows, err
	}

	return tx, rows, err
}

// insert, update, delete 쿼리 또는 프로시져인 경우 tx.Rollback(), tx.Commit() 호출 필수
func TxExecDB(query string) (*sql.Tx, error) {
	if DBc == nil {
		time.Sleep(10 * time.Millisecond)
	}

	tx, err := DBc.Begin()
	if err != nil {
		Lprintf(1, "[ERR ] Begin : %s\n", err)
		return tx, err
	}

	//result, err := tx.Exec(query)
	_, err = tx.Exec(query)
	if err != nil {
		Lprintf(1, "[ERR ] Query : %s\n", err)
		return tx, err
	}

	// rowAffect, _ := result.RowsAffected()
	// lastId, _ := result.LastInsertId()
	// Lprintf(4, "[INFO] rowAffect : [%d], lastId : [%d]\n", rowAffect, lastId)

	return tx, err
}

// 프로시저 응답코드 처리
func GetRespCode(rows *sql.Rows, procName string) (int, MessageValue) {
	var result int
	var msgKey string       //유효성 메세지 key
	var msg MessageValue    //응답 메세지에 들어갈 메세지 구조체 (value)
	var vKey, vValue string //유효성 메세지 치환자

	for rows.Next() {
		if err := rows.Scan(&result); err != nil {
			Lprintf(1, "[ERR ] %s first return scan error : %s\n", procName, err)
			result = 99
			return result, msg
		}

		if result == 99 { // 프로시저 에러
			Lprintf(1, "[ERR ] dbms error %s : %d\n", procName, result)
			return result, msg
		}

		if result == 10 { // 유효성 코드만 존재
			Lprintf(4, "[INFO] %s is Result Code : %d, Next Result Set\n", procName, result)
			if rows.NextResultSet() {
				for rows.Next() {
					if err := rows.Scan(&msgKey); err != nil {
						Lprintf(1, "[ERR ] sql scan error(%s)\n", err.Error())
						return result, msg
					}
				}
			}

			msg, ok := GetValidationMap(msgKey)
			if !ok {
				msg.Cn = "A system error has occurred. If the problem persists, please contact the customer service center."
				msg.Kr = "A system error has occurred. If the problem persists, please contact the customer service center."
				msg.En = "A system error has occurred. If the problem persists, please contact the customer service center."
			}

			return result, msg
		}
		if result == 11 { // 유효성 코드,치환자 존재
			Lprintf(4, "[ERR ] %s is not satisfied with conditions : %d\n", procName, result)
			if rows.NextResultSet() {
				for rows.Next() {
					if err := rows.Scan(&msgKey); err != nil {
						Lprintf(1, "[ERR ] sql scan error(%s)\n", err.Error())
						return result, msg
					}
				}
			}

			msg, ok := GetValidationMap(msgKey)
			if !ok {
				msg.Cn = "A system error has occurred. If the problem persists, please contact the customer service center."
				msg.Kr = "A system error has occurred. If the problem persists, please contact the customer service center."
				msg.En = "A system error has occurred. If the problem persists, please contact the customer service center."
			}

			if rows.NextResultSet() {
				for rows.Next() {
					if err := rows.Scan(&vKey, &vValue); err != nil {
						Lprintf(1, "[ERR ] sql scan error(%s)\n", err.Error())
						return result, msg
					}
					msg.Cn = strings.Replace(msg.Cn, vKey, vValue, -1)
					msg.Kr = strings.Replace(msg.Kr, vKey, vValue, -1)
					msg.En = strings.Replace(msg.En, vKey, vValue, -1)
				}
			}
		}
	}

	return result, msg
}

// 프로시저 응답코드 처리 -> db sync가 필요한 경우 사용
func GetRespCodeSync(rows *sql.Rows, procName string) int {
	var result int

	for rows.Next() {
		if err := rows.Scan(&result); err != nil {
			Lprintf(1, "[ERR ] %s first return scan error : %s\n", procName, err)
			result = -1
			return result
		}

		if result < 0 { // 프로시저 에러
			Lprintf(1, "[ERR ] dbms error %s : %d\n", procName, result)
			return result
		} else if result > 0 {
			go NotiDbAgent(result)

		}
	}

	return result
}

func NotiDbAgent(reportIdx int) {
	sIdx := fmt.Sprintf("%d:salt", reportIdx)

	url := "http://" + Dbip[ConnIdx] + ":" + DBAgentPort + "/dbagent/notify?idx=" + EEncode([]byte(sIdx))
	req, err := http.NewRequest("GET", url, nil)
	Lprintf(4, "[INFO] noti request (%s)", url)

	req.Header.Set("Connection", "close")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		Lprintf(1, "[FAIL] noti request error (%s)", err)
		return
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		Lprintf(1, "[FAIL] noti response error (%s)", err)
		return
	}
	Lprintf(4, "[INFO] noti response (%s)", resp.Status)
	return
}

/*
// DBMS Transaction 쿼리
// insert, update, delete 쿼리 또는 프로시져인 경우 tx.Rollback(), tx.Commit() 호출 필수
// select 또는 resultSet이 return되는 프로시져인 경우 rows.Close() 호출 필수
func TxQuery22DB(query []string) (*sql.Tx, *sql.Rows, error) {
	if DBc == nil {
		time.Sleep(10 * time.Millisecond)
	}

	tx, err := DBc.Begin()
	if err != nil {
		Lprintf(1, "[ERR ] Begin : %s\n", err)
		return tx, nil, err
	}
for{}
	rows, err := tx.Query(query[0])
	if err != nil {
		Lprintf(1, "[ERR ] Query : %s\n", err)
		return tx, rows, err
	}
}
	return tx, rows, err
}
*/
