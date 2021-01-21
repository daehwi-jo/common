package cls

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	WireshartLen = 2048
)

// MIME TYPE upload
// path : file path 이고 파일명은 제외
// r    : http request 포인터
func HttpDataMultiPartUploading(path string, r *http.Request) []string {

	Lprintf(4, "[INFO] multipartuploading read start\n")

	var fileName []string

	reader, err := r.MultipartReader()
	if err != nil {
		Lprintf(1, "[Err ] reader error : [%s]\n", err)
		return nil
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			Lprintf(4, "[INFO] multipart data EOF\n")
			break
		}

		if part.FileName() == "" {
			Lprintf(4, "[INFO] multipart file name is not existed\n")
			continue
		} else {
			fileName = append(fileName, part.FileName())
			Lprintf(4, "[INFO] fileName : [%s]\n", part.FileName())
		}

		path = strings.TrimRight(path, "/")                                        // path 뒤에 "/" 문자오면 제거
		bfile := fmt.Sprintf("%s/%s_%d", path, part.FileName(), time.Now().Unix()) // 파일저장
		Lprintf(4, "[INFO] save file path : [%s]\n", bfile)
		input, err := os.Create(bfile)
		if err != nil {
			Lprintf(1, "[Err ] file create error : %s\n", err)
			return nil
		}
		defer input.Close()

		if _, err := io.Copy(input, part); err != nil {
			Lprintf(1, "[Err ] copy err : [%s]\n", err)
			return nil
		}

		// 다운로드가 다 되었으므로 tmp -> origin binary로 overwrite
		nfile := fmt.Sprintf("%s/package/%s", ConfDir, part.FileName())
		if err := os.Rename(bfile, nfile); err != nil {
			Lprintf(1, "[Err ] file rename : %s\n", err)
			return nil
		}
	}

	Lprintf(4, "[INFO] multipartuploading read end\n")

	return fileName
}

// file upload
func HttpDataUploading(path string, r *http.Request) bool {

	//Lprintf(4, "[INFO] path : %s\n", path)
	input, err := os.Create(path)
	if err != nil {
		Lprintf(1, "[Err ] file create error : %s\n", err)
		return false
	}
	defer input.Close()

	contentLen := r.Header.Get("Content-Length")

	Lprintf(4, "[INFO] uploading read start - length : [%s], path : [%s]\n", contentLen, path)
	if _, err := io.Copy(input, r.Body); err != nil {
		Lprintf(1, "[Err ] install file copy err : %s\n", err)
		return false
	}

	Lprintf(4, "[INFO] uploading read end\n")

	return true
}

// file download
func HttpDataDownloading(path string, h http.ResponseWriter) bool {

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
	if err != nil {
		Lprintf(1, "[Err ] stat error : %s\n", err)
		return false
	}
	contentLen := fStat.Size()

	h.Header().Set("Content-Length", strconv.FormatInt(contentLen, 10))
	h.Header().Set("Content-Type", "application/*")

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
		h.Write(instFile[:n])
	}
	Lprintf(4, "[INFO] downloading read end\n")

	return true
}
