package cls

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
	_ "github.com/go-sql-driver/mysql"
)

var DBc *sql.DB

var Squery map[string]string
var Iquery map[string]string
var Uquery map[string]string
var Dquery map[string]string

var Dbbd string   // dbms brand - mssql, mysql
var Dbid string   // dbms id
var Dbps string   // dbms password
var Dbpt string   // dbms port
var Dbnm string   // dbms instance
var Dbip []string // dbms ip
var DbTimeOut int // dbms timeout
var ConnIdx int   // 현재 접속중인 ip 배열 index - 최초는 0번째 ip로 연결
var ConnLen int   // 접속할 ip 갯수
var Qtimeout int  // Query Timeout이 발생한 횟수

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

func db_conf(fname string) int {
	var r RESULT

	Lprintf(4, "[INFO] conf start (%s)\n", fname)

	// dbms connect address
	Dbip, r = GetTokenValues("HOST_DBMS", fname, "&")
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS not exist value\n")
		return (-1)
	}
	ConnLen = len(Dbip)
	Lprintf(4, "[INFO] ConnLen : [%d]\n", ConnLen)

	for i, _ := range Dbip {
		Lprintf(4, "[INFO] Dbip[%d] : [%s]\n", i, Dbip[i])
		// localhost -> 127.0.0.1
		if strings.ToLower(Dbip[i]) == "localhost" {
			Dbip[i] = "127.0.0.1"
		}
	}

	// dbms connect id
	Dbid, r = GetTokenValue("ID_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_ID not exist value\n")
		return (-1)
	}
	Lprintf(4, "[INFO] Dbid : [%s]\n", Dbid)
	// dbms connect password
	Dbps, r = GetTokenValue("PASSWD_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_PASS not exist value\n")
		return (-1)
	}
	Lprintf(4, "[INFO] Dbps : [%s]\n", Dbps)

	// dbms instance name
	Dbnm, r = GetTokenValue("NAME_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_DB not exist value\n")
		return (-1)
	}
	Lprintf(4, "[INFO] Dbnm : [%s]\n", Dbnm)

	// dbms instance name
	Dbpt, r = GetTokenValue("PORT_DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_DB not exist value\n")
		return (-1)
	}
	Lprintf(4, "[INFO] Dbpt : [%s]\n", Dbpt)

	// dbms brand
	Dbbd, r = GetTokenValue("DBMS", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_DB not exist value\n")
		Dbbd = "mysql"
	}
	Lprintf(4, "[INFO] Dbbd : [%s]\n", Dbbd)

	DBc, _ = Initdb(Dbbd, Dbid, Dbps, Dbip[0], Dbpt, Dbnm)

	if DBc == nil {
		return (-1)
	}

	// dbms timeout
	dbTimeout, r := GetTokenValue("DBMS_TIMEOUT", fname)
	if r == CONF_ERR {
		Lprintf(1, "[FAIL] DBMS_TIMEOUT not exist value, so set 10 seconds\n")
		dbTimeout = "10" // db query timeout config에 미설정시 default 값으로 10초 설정
		//return (-1)
	}
	DbTimeOut, _ = strconv.Atoi(dbTimeout)
	Lprintf(4, "[INFO] DbTimeOut : %d\n", DbTimeOut)

	//DBc.SetConnMaxLifetime(time.Second * time.Duration(DbTimeOut))

	return 0
}

func Initdb(dbbd, dbid, dbps, dbip, dbpt, dbnm string) (*sql.DB, error) {
	Lprintf(4, "[INFO] new db connection try %s", dbip)

	var c *sql.DB
	var err error

	if dbbd == "mssql" {
		c, err = sql.Open("mssql", "server="+dbip+";user id="+dbid+";password="+dbps+";database="+dbnm)
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

	return c, nil
}

// DBMS 헬스체크 - 사용하지 않음
func CheckDbmsLive() error {

	dbp, err := Initdb(Dbbd, Dbid, Dbps, Dbip[ConnIdx], Dbpt, Dbnm)
	if err != nil {
		return err
	}
	defer dbp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(DbTimeOut))
	defer cancel()

	// DB서버가 Timeout 이라고 판단하고 헬스체크 (ping) 후 판단
	startTime := time.Now()
	err = dbp.PingContext(ctx)
	finTime := time.Since(startTime)
	Lprintf(4, "[INFO] DBMS ping response (%s)\n", finTime)

	return err
}

// config에 등록된 다른 DBMS로 연결한다.
func DbmsDuplexing() {
	var err error

	// 돌아가면서 접속을 해야하므로 next index를 체크한다.
	if ConnLen > 0 {
		ConnIdx++
		if ConnIdx == ConnLen {
			ConnIdx = 0
		}
	}

	if err = DBc.Close(); err != nil { // 기존 DB 해지
		Lprintf(1, "[ERR ] DBc close is error : [%s]\n", err)
	}

	DBc, err = Initdb(Dbbd, Dbid, Dbps, Dbip[ConnIdx], Dbpt, Dbnm)
	if err != nil {
		Lprintf(1, "[ERR ] dbms reconnect error\n")
	}

	return
}

// DBMS retry 기능이 들어간 쿼리
func QueryDB(query string) (*sql.Rows, error) {
	rows, err := DBc.Query(query)
	//Lprintf(4, "[INFO] query resp string : %s\n", err)
	if err != nil {
		Lprintf(1, "[ERR ] Query error : %s \n", err)
		// try one more
		return DBc.Query(query)
	}
	return rows, err
}

// DBMS Timeout 기능이 들어간 쿼리
// cancel() - Canceling this context releases resources associated with it, so code should call cancel as soon as the operations running in this Context complete
// https://github.com/go-sql-driver/mysql/issues/836
func QueryTimeOut(query string) (*sql.Rows, uint, context.CancelFunc) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(DbTimeOut))
	rows, err := DBc.QueryContext(ctx, query)

	//Lprintf(4, "[INFO] query resp string : %s\n", err)
	if err != nil {
		Lprintf(1, "[ERR ] QueryContext : %s time \n", err)

		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no route to host") {
			// 서버 접속이 안됨으로 판단하고 DB Session 교체
			DbmsDuplexing()
			Lprintf(4, "[INFO] DBMS down, so changed\n")
			return nil, DBCONN_ERR, cancel

		} else if strings.Contains(err.Error(), "context deadline exceeded") || strings.Contains(err.Error(), "connection timed out") {
			err = CheckDbmsLive()
			if err != nil {
				DbmsDuplexing()
				Lprintf(4, "[INFO] DBMS down(%s), so changed\n", err.Error())
				return nil, DBCONN_ERR, cancel
			}
			Lprintf(4, "[INFO] DBMS live, but response is slow so not changed\n")
			return nil, DBCONN_DECLINE, cancel

		} else {
			Lprintf(1, "[ERR ] query error : %s\n", err)
			return nil, DBETC_ERR, cancel
		}
	}
	//defer cancel() // releases resources if slowOperation completes before timeout elapses

	return rows, 0, cancel
}

func InitQuery(qset []QuerySet) int {
	Lprintf(4, "[INFO] db query setting (%d) ", len(qset))
	for i := 0; i < len(qset); i++ {
		switch qset[i].Qtype {
		case SELECT:
			Squery[qset[i].Qname] = qset[i].Query
		case UPDATE:
			Uquery[qset[i].Qname] = qset[i].Query
		case INSERT:
			Iquery[qset[i].Qname] = qset[i].Query
		case DELETE:
			Dquery[qset[i].Qname] = qset[i].Query
		default:
			return (-1)
		}
	}

	return 0
}

func SetWebData(rows *sql.Rows) []WebData {
	data := []WebData{}

	for i := 0; rows.Next() != false; i++ {
		cols, _ := rows.Columns()
		da := make(WebData, len(cols))
		tmps := make([]string, len(cols))

		switch len(cols) {
		case 1:
			rows.Scan(&tmps[0])
		case 2:
			rows.Scan(&tmps[0], &tmps[1])
		case 3:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2])
		case 4:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2], &tmps[3])
		case 5:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2], &tmps[3], &tmps[4])
		case 6:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2], &tmps[3], &tmps[4], &tmps[5])
		case 7:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2], &tmps[3], &tmps[4], &tmps[5], &tmps[6])
		case 8:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2], &tmps[3], &tmps[4], &tmps[5], &tmps[6], &tmps[7])
		case 9:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2], &tmps[3], &tmps[4], &tmps[5], &tmps[6], &tmps[7], &tmps[8])
		case 10:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2], &tmps[3], &tmps[4], &tmps[5], &tmps[6], &tmps[7], &tmps[8], &tmps[9])
		case 11:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2], &tmps[3], &tmps[4], &tmps[5], &tmps[6], &tmps[7], &tmps[8], &tmps[9], &tmps[10])
		case 12:
			rows.Scan(&tmps[0], &tmps[1], &tmps[2], &tmps[3], &tmps[4], &tmps[5], &tmps[6], &tmps[7], &tmps[8], &tmps[9], &tmps[10], &tmps[11])
		default:
			Lprintf(1, "[FAIL] column count is too big")
			return nil
		}

		Lprintf(4, "[INFO] column data example (%s)", tmps[0])
		for i := 0; i < len(cols); i++ {
			da[cols[i]] = tmps[i]
		}

		data = append(data, da)
	}

	return data
}
