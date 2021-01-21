package cls

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/labstack/echo"
)

const (
	WireshartLen = 2048
)

// create directory
func MakeDir(dirPath string) int {

	// file mode is drwxr-x---
	if err := os.MkdirAll(dirPath, 0750); err != nil {
		Lprintf(1, "[ERROR] dir(%s) make fail(%s) \n", dirPath, err.Error())
		return -1
	}

	return 1
}

// echo framework multipart file uploading
func EchoHttpDataMultiPartUploading(path string, c echo.Context) []string {
	var fileName []string

	form, err := c.MultipartForm()
	if err != nil {
		Lprintf(1, "[ERR ] MultipartForm : %s\n", err)
		return nil
	}

	files := form.File["files"] // client html form name value

	for _, file := range files {

		if file.Size == 0 {
			break
		}
		src, err := file.Open()
		if err != nil {
			return nil
		}
		defer src.Close()

		if MakeDir(path) < 0 {
			Lprintf(1, "[ERR ] MakeDir : %s\n", path)
			return nil
		}

		Lprintf(4, "[INFO] create file path(%s) file(%s)\n", path, file.Filename)

		dst, err := os.Create(path + "/" + file.Filename)
		if err != nil {
			Lprintf(1, "[ERR ] %s Create : %s\n", file.Filename, err)
			return nil
		}
		defer dst.Close()

		if _, err = io.Copy(dst, src); err != nil {
			Lprintf(1, "[ERR ] %s Copy : %s\n", file.Filename, err)
			return nil
		}

		fileName = append(fileName, file.Filename)
	}

	return fileName
}

// echo framework로 파일 업/다운로드 시 사용가능 함수 추가
// echo framework file upload
func EchoHttpDataUploading(path string, c echo.Context) bool {

	//Lprintf(4, "[INFO] path : %s\n", path)
	input, err := os.Create(path)
	if err != nil {
		Lprintf(1, "[Err ] file create error : %s\n", err)
		return false
	}
	defer input.Close()

	contentLen := c.Request().Header.Get("Content-Length")

	Lprintf(4, "[INFO] uploading read start - length : [%s], path : [%s]\n", contentLen, path)
	if _, err := io.Copy(input, c.Request().Body); err != nil {
		Lprintf(1, "[Err ] install file copy err : %s\n", err)
		return false
	}

	Lprintf(4, "[INFO] uploading read end\n")

	return true
}

// echo framework file download function
func EchoHttpDataDownloading(path string, c echo.Context) bool {

	//Lprintf(4, "[INFO] path : %s\n", path)
	// file read 후 client write 하기
	instFile := make([]byte, WireshartLen) // wireshark 에 찍힌 length로 설정

	fd, err := os.Open(path)
	if err != nil {
		Lprintf(1, "[Err ] open err : %s\n", err)
		return false
	}
	defer fd.Close()

	fStat, err := os.Stat(path)
	if os.IsNotExist(err) { // exist file
		Lprintf(1, "[Err ] stat error : %s\n", err)
		return false
	}
	contentLen := fStat.Size()

	c.Response().Header().Set("Content-Length", strconv.FormatInt(contentLen, 10))
	c.Response().Header().Set("Content-Type", "application/*")

	Lprintf(4, "[INFO] downloading read start - length : [%d], path : [%s]\n", contentLen, path)
	for {
		n, err := fd.Read(instFile)
		if n == 0 {
			Lprintf(4, "[INFO] %s read end\n", path)
			break
		}

		if err != nil {
			Lprintf(1, "[Err ] read error : %s", err)
			return false
		}

		// write 하면 됨
		c.Response().Write(instFile[:n])
	}
	Lprintf(4, "[INFO] downloading read end\n")

	return true
}

// File Copy
// 파일명까지 full명으로 파라미터 입력 필요!!
func SetFileCopy(srcFile string, destFile string, perm os.FileMode) bool {
	// copy
	input, err := ioutil.ReadFile(srcFile)
	if err != nil {
		Lprintf(1, "[ERR ] ReadFile : %s\n", err)
		return true
	}

	// 경로 생성
	var fDir string
	tmpDir := strings.Split(destFile, "/")
	for i := 0; i < len(tmpDir)-1; i++ {
		fDir += fmt.Sprintf("%s/", tmpDir[i])
	}
	fDir = strings.TrimRight(fDir, "/")

	if MakeDir(fDir) == -1 {
		return false
	}

	err = ioutil.WriteFile(destFile, input, perm)
	if err != nil {
		Lprintf(1, "[ERR ] WriteFile : %s\n", err)
		return true
	}

	return false
}
