package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	if !workerEnabled() {
		return "", errors.New("日志解密需要配置 Cloudflare Worker")
	}
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
	var output strings.Builder
	for offset := 1; offset < len(lines); offset += 32 {
		end := offset + 32
		if end > len(lines) {
			end = len(lines)
		}
		batch := []string{}
		positions := []int{}
		for index := offset; index < end; index++ {
			line := strings.TrimSpace(string(lines[index]))
			if line != "" {
				batch = append(batch, line)
				positions = append(positions, index+1)
			}
		}
		if len(batch) == 0 {
			continue
		}
		var result struct {
			Lines []struct {
				Text  string `json:"text"`
				Error string `json:"error"`
			} `json:"lines"`
		}
		if err := callWorkerJSON("/v1/logs/decrypt", map[string]interface{}{"header": header, "lines": batch}, &result); err != nil {
			return "", err
		}
		if len(result.Lines) != len(batch) {
			return "", errors.New("日志解密响应数量不一致")
		}
		for index, line := range result.Lines {
			if line.Error != "" {
				output.WriteString(fmt.Sprintf("[日志解密错误 行=%d] %s\n", positions[index], line.Error))
				continue
			}
			output.WriteString(formatSecureLogEvent([]byte(line.Text)))
			output.WriteString("\n")
		}
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
