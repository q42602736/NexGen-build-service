package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var workerHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func workerEnabled() bool {
	return cfg.WorkerURL != ""
}

func newWorkerRequest(method, path string, body io.Reader) (*http.Request, error) {
	if !workerEnabled() || cfg.WorkerToken == "" {
		return nil, fmt.Errorf("未配置 Cloudflare Worker")
	}
	req, err := http.NewRequest(method, strings.TrimRight(cfg.WorkerURL, "/")+path, body)
	if err != nil {
		return nil, fmt.Errorf("创建 Worker 请求失败")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.WorkerToken)
	return req, nil
}

func callWorkerJSON(path string, input, output interface{}) error {
	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("Worker 请求编码失败")
	}
	req, err := newWorkerRequest(http.MethodPost, path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := workerHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("Worker 服务暂时不可用")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Worker 拒绝请求，状态码 %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32*1024*1024)).Decode(output); err != nil {
		return fmt.Errorf("Worker 响应格式无效")
	}
	return nil
}

func signWorkerToken(claims interface{}, kind string) (string, error) {
	var result struct {
		Token string `json:"token"`
	}
	err := callWorkerJSON("/v1/auth/sign", map[string]interface{}{"claims": claims, "kind": kind}, &result)
	if err == nil && result.Token == "" {
		err = fmt.Errorf("Worker 未返回令牌")
	}
	return result.Token, err
}

func verifyAdminPassword(password string) (bool, error) {
	if !workerEnabled() {
		return secureCompareString(cfg.AdminPassword, password), nil
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	err := callWorkerJSON("/v1/auth/admin", map[string]string{"password": password}, &result)
	return result.Valid, err
}

func (g *GitHubClient) newGitHubRequest(method, upstream string, body io.Reader) (*http.Request, error) {
	if workerEnabled() {
		parsed, err := url.Parse(upstream)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "api.github.com" || parsed.User != nil {
			return nil, fmt.Errorf("GitHub 请求地址无效")
		}
		path := "/github" + parsed.EscapedPath()
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		return newWorkerRequest(method, path, body)
	}
	req, err := http.NewRequest(method, upstream, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+g.Token)
	return req, nil
}
