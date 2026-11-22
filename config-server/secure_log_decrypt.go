package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

const (
	secureLogHeaderPrefix     = "XBOARD_SECURE_LOG_V1 "
	secureLogUploadLimitBytes = 20 * 1024 * 1024
)

type secureLogHeader struct {
	Algorithm string `json:"alg"`
	Key       string `json:"key"`
	CreatedAt string `json:"createdAt"`
}

type secureLogRecord struct {
	Nonce      string `json:"n"`
	Ciphertext string `json:"c"`
}

type secureLogEvent struct {
	Time    string `json:"time"`
	Source  string `json:"source"`
	Message string `json:"message"`
	Error   string `json:"error"`
	Stack   string `json:"stack"`
}

var secureLogKeyCache struct {
	once sync.Once
	key  *rsa.PrivateKey
	err  error
}

func loadSecureLogPrivateKey() (*rsa.PrivateKey, error) {
	secureLogKeyCache.once.Do(func() {
		block, _ := pem.Decode([]byte(getEnv("SECURE_LOG_PRIVATE_KEY", "")))
		if block == nil {
			secureLogKeyCache.err = errors.New("专用二进制未包含有效的日志解密私钥")
			return
		}
		if block.Type == "RSA PRIVATE KEY" {
			secureLogKeyCache.key, secureLogKeyCache.err = x509.ParsePKCS1PrivateKey(block.Bytes)
			return
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			secureLogKeyCache.err = errors.New("日志解密私钥格式无效")
			return
		}
		var ok bool
		secureLogKeyCache.key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			secureLogKeyCache.err = errors.New("日志解密私钥类型无效")
		}
	})
	return secureLogKeyCache.key, secureLogKeyCache.err
}

func (h *Handlers) DecryptSecureLog(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, secureLogUploadLimitBytes)
	if err := r.ParseMultipartForm(secureLogUploadLimitBytes); err != nil {
		jsonError(w, "日志文件过大或表单无效，最大支持 20MB", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "请选择 .xblog 日志文件", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if header != nil && !strings.HasSuffix(strings.ToLower(header.Filename), ".xblog") {
		jsonError(w, "只支持 .xblog 日志文件", http.StatusBadRequest)
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, secureLogUploadLimitBytes+1))
	if err != nil {
		jsonError(w, "读取日志文件失败", http.StatusBadRequest)
		return
	}
	if int64(len(data)) > secureLogUploadLimitBytes {
		jsonError(w, "日志文件过大，最大支持 20MB", http.StatusBadRequest)
		return
	}

	output, err := decryptSecureLogBytes(data)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonResponse(w, map[string]string{
		"filename": header.Filename,
		"content":  output,
	})
}

func decryptSecureLogBytes(data []byte) (string, error) {
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) == 0 {
		return "", errors.New("无效日志文件：内容为空")
	}
	headerLine := strings.TrimRight(string(lines[0]), "\r")
	if !strings.HasPrefix(headerLine, secureLogHeaderPrefix) {
		return "", fmt.Errorf("无效日志文件：缺少 %s 头", secureLogHeaderPrefix)
	}
	var header secureLogHeader
	if err := json.Unmarshal([]byte(strings.TrimPrefix(headerLine, secureLogHeaderPrefix)), &header); err != nil {
		return "", fmt.Errorf("日志头解析失败：%w", err)
	}
	if header.Key == "" {
		return "", errors.New("日志头缺少加密会话密钥")
	}
	privateKey, err := loadSecureLogPrivateKey()
	if err != nil {
		return "", err
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(header.Key)
	if err != nil {
		return "", errors.New("日志会话密钥编码无效")
	}
	rawKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, wrappedKey, nil)
	if err != nil {
		return "", errors.New("日志会话密钥解密失败")
	}
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return "", errors.New("日志会话密钥长度无效")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("日志解密初始化失败")
	}
	var output strings.Builder
	for index := 1; index < len(lines); index++ {
		line := strings.TrimSpace(string(lines[index]))
		if line == "" {
			continue
		}
		var record secureLogRecord
		if json.Unmarshal([]byte(line), &record) != nil {
			output.WriteString(fmt.Sprintf("[日志解密错误 行=%d] 日志记录格式无效\n", index+1))
			continue
		}
		nonce, nonceErr := base64.StdEncoding.DecodeString(record.Nonce)
		data, dataErr := base64.StdEncoding.DecodeString(record.Ciphertext)
		if nonceErr != nil || dataErr != nil || len(nonce) != gcm.NonceSize() {
			output.WriteString(fmt.Sprintf("[日志解密错误 行=%d] 日志记录编码无效\n", index+1))
			continue
		}
		plain, err := gcm.Open(nil, nonce, data, nil)
		if err != nil {
			output.WriteString(fmt.Sprintf("[日志解密错误 行=%d] 日志记录解密失败\n", index+1))
			continue
		}
		output.WriteString(formatSecureLogEvent(plain))
		output.WriteString("\n")
	}
	return output.String(), nil
}

func formatSecureLogEvent(plain []byte) string {
	var event secureLogEvent
	if err := json.Unmarshal(plain, &event); err != nil {
		return fmt.Sprintf("[format-error] %v raw=%s", err, string(plain))
	}

	var output strings.Builder
	output.WriteString("[")
	output.WriteString(event.Time)
	output.WriteString("][")
	output.WriteString(event.Source)
	output.WriteString("] ")
	output.WriteString(event.Message)
	if event.Error != "" {
		output.WriteString("\n  error: ")
		output.WriteString(event.Error)
	}
	if event.Stack != "" {
		output.WriteString("\n")
		output.WriteString(event.Stack)
	}
	return output.String()
}
