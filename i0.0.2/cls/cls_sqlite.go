package cls

import (
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var SqliteDB *sql.DB

func SqliteInit(fname string) error {
	db, err := sql.Open("sqlite3", fname)
	if err != nil {
		Lprintf(1, "[DB ERR] Sqlite FILE CREATE  error (%s)", err)
		return err
	}

	SqliteDB = db
	return nil
}

func CreateReqTable() bool {
	if SqliteDB == nil {
		return false
	}

	query := "CREATE TABLE IF NOT EXISTS REQUEST_INFO (reqKey VARCHAR(255) , command VARCHAR(20), url VARCHAR(1024), status INTEGER, time VARCHAR(20) ,ip VARCHAR(20) ,port VARCHAR(10),result text)"
	statement, err := SqliteDB.Prepare(query)
	if err != nil {
		Lprintf(1, "[DB ERR] create statement error (%s)", err)
		return false
	}
	defer statement.Close()

	_, err = statement.Exec()

	if err != nil {
		Lprintf(1, "[DB ERR] create table error (%s)", err)
		return false
	}

	return true
}

func DeleteReqTable() bool {

	if SqliteDB == nil {
		return false
	}

	statement, _ := SqliteDB.Prepare("DELETE FROM REQUEST_INFO  WHERE time < datetime('now','localtime','-5 minutes') ")
	defer statement.Close()

	_, err := statement.Exec()
	if err != nil {
		Lprintf(1, "[DB ERR] delete base error (%s)", err)
		return false
	}

	return true
}

func SelectReqStatus(reqKey, command string) (bool, int, string) {
	var status int
	var intime string

	if SqliteDB == nil {
		return false, 0, ""
	}
	// Lprintf(4, "[INFO] request info select start \n")

	rows, err := SqliteDB.Query("SELECT status, time FROM REQUEST_INFO WHERE reqKey=? and command =? and status=0 ", reqKey, command)
	defer rows.Close()

	if err != nil {
		Lprintf(1, "[WARN] BASE info select query fail (%s)\n", err)
		return false, 0, ""
	}

	// only 1 row select
	for rows.Next() {
		if err := rows.Scan(&status, &intime); err != nil {
			Lprintf(4, "[INFO] DATA BASE row scan error (%s)\n", err)
			continue
		}
		return true, status, intime
	}

	return false, 0, ""
}

func SelectCheckValue(regkey, command, ip, port string) (bool, int) {
	var status int

	if SqliteDB == nil {
		return false, 0
	}
	// Lprintf(4, "[INFO] request info select start \n")

	rows, err := SqliteDB.Query("SELECT status FROM REQUEST_INFO WHERE reqkey=? and command=? and ip =? and port = ? and status=0 ", regkey, command, ip, port)
	defer rows.Close()

	if err != nil {
		Lprintf(1, "[WARN] BASE info select query fail (%s)\n", err)
		return false, 0
	}

	// only 1 row select
	for rows.Next() {
		if err := rows.Scan(&status); err != nil {
			Lprintf(4, "[INFO] DATA BASE row scan error (%s)\n", err)
			continue
		}
		return true, status
	}

	return false, 0
}

func SelectResultValue(regkey, command, ip string) string {
	var result string

	if SqliteDB == nil {
		return ""
	}
	// Lprintf(4, "[INFO] request info select start \n")

	//and time > datetime('now','localtime','-2 minutes')
	rows, err := SqliteDB.Query("SELECT result FROM REQUEST_INFO WHERE reqkey=? and command=? and ip =? and status=1   order by time desc limit 1  ", regkey, command, ip)
	defer rows.Close()

	if err != nil {
		Lprintf(1, "[WARN] BASE info select query fail (%s)\n", err)
		return ""
	}

	// only 1 row select
	for rows.Next() {
		if err := rows.Scan(&result); err != nil {
			Lprintf(4, "[INFO] DATA BASE row scan error (%s)\n", err)
			continue
		}
		return result
	}

	return ""
}

func InsertRequest(reqKey, command, url, ip, port string) bool {
	if SqliteDB == nil {
		return false
	}

	intime := string(time.Now().String()[:19])
	//Lprintf(4, "[DB INFO] insert time (%s)", intime)
	statement, err := SqliteDB.Prepare("INSERT INTO REQUEST_INFO (reqKey, command, url, ip, port, time, status) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		Lprintf(1, "[DB ERR] create statement error (%s)", err)
		return false
	}
	defer statement.Close()

	_, err = statement.Exec(reqKey, command, url, ip, port, intime, REQ_START)
	if err != nil {
		Lprintf(1, "[DB ERR] insert base error (%s)", err)
		return false
	}
	//Lprintf(4, "[DB INFO] insert base success(%s, %s)", reqKey, command)

	return true
}

func UpdateRequest(reqKey, command, ip, port string, status RESULT) bool {
	if SqliteDB == nil {
		return false
	}

	statement, err := SqliteDB.Prepare("UPDATE REQUEST_INFO SET status = ? WHERE reqkey = ? and command= ? and ip= ?  and port= ?")
	if err != nil {
		Lprintf(1, "[DB ERR] create statement error (%s)", err)
		return false
	}
	defer statement.Close()

	_, err = statement.Exec(status, reqKey, command, ip, port)
	if err != nil {
		Lprintf(1, "[DB ERR] update request error (%s)", err)
		return false
	}
	//Lprintf(4, "[DB INFO] update request success(%s, %d)", reqKey, status)

	return true
}

func UpdateResult(reqKey, command, ip, port, strResult string) bool {
	if SqliteDB == nil {
		return false
	}

	statement, err := SqliteDB.Prepare("UPDATE REQUEST_INFO SET result = ? ,status=1 WHERE reqkey = ? and command= ? and ip= ?  and port= ?")
	if err != nil {
		Lprintf(1, "[DB ERR] create statement error (%s)", err)
		return false
	}
	defer statement.Close()

	_, err = statement.Exec(strResult, reqKey, command, ip, port)
	if err != nil {
		Lprintf(1, "[DB ERR] update request error (%s)", err)
		return false
	}
	//Lprintf(4, "[DB INFO] update request success(%s, %d)", reqKey, strResult)

	return true
}

func UpdateStaus(status int, ip, port, command string) bool {
	if SqliteDB == nil {
		return false
	}

	statement, err := SqliteDB.Prepare("UPDATE REQUEST_INFO SET status=? WHERE ip= ?  and port= ? and command= ?")
	if err != nil {
		Lprintf(1, "[DB ERR] create statement error (%s)", err)
		return false
	}
	defer statement.Close()

	_, err = statement.Exec(status, ip, port, command)
	if err != nil {
		Lprintf(1, "[DB ERR] update request error (%s)", err)
		return false
	}
	//Lprintf(4, "[DB INFO] update request success(%d)", ip)

	return true
}

func SelectCommandValue(ip, port string) (string, string, string) {
	var command, reqkey, param string

	if SqliteDB == nil {
		return "", "", ""
	}
	// Lprintf(4, "[INFO] request info select start \n")

	//and time > datetime('now','localtime','-2 minutes')
	rows, err := SqliteDB.Query("SELECT command,reqkey,url FROM REQUEST_INFO WHERE  ip =? and port = ? and command in ('regist','transfer') order by time desc limit 1  ", ip, port)
	defer rows.Close()

	if err != nil {
		Lprintf(1, "[WARN] BASE info select query fail (%s)\n", err)
		return "", "", ""
	}

	// only 1 row select
	for rows.Next() {
		if err := rows.Scan(&command, &reqkey, &param); err != nil {
			Lprintf(4, "[INFO] DATA BASE row scan error (%s)\n", err)
			continue
		}
		return command, reqkey, param
	}

	return "", "", ""
}
