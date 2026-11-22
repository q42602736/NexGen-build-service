package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const maxBuildAuditOSSConfigContentBytes = 512 * 1024
const buildAuditRemoteOSSFetchTimeout = 10 * time.Second

var remoteOSSHTTPClient = newRemoteOSSHTTPClient()

type BuildRecordAudit struct {
	RecordID                   int64  `json:"record_id"`
	CodeID                     int    `json:"code_id"`
	CodeName                   string `json:"code_name"`
	RequestID                  string `json:"request_id"`
	Client                     string `json:"client"`
	Profile                    string `json:"profile"`
	Tag                        string `json:"tag"`
	Branch                     string `json:"branch"`
	Core                       string `json:"core"`
	Platforms                  string `json:"platforms"`
	Status                     string `json:"status"`
	Conclusion                 string `json:"conclusion"`
	RunID                      int64  `json:"run_id"`
	RunURL                     string `json:"run_url"`
	ProfileBlobSHA             string `json:"profile_blob_sha"`
	ProfileContentSHA256       string `json:"profile_content_sha256"`
	RemoteConfigSnapshot       string `json:"remote_config_snapshot"`
	RemoteConfigSnapshotSHA256 string `json:"remote_config_snapshot_sha256"`
	OSSConfigContent           string `json:"oss_config_content"`
	OSSConfigContentSHA256     string `json:"oss_config_content_sha256"`
	OSSConfigContentFormat     string `json:"oss_config_content_format"`
	OSSConfigSourceName        string `json:"oss_config_source_name"`
	OSSConfigURL               string `json:"oss_config_url"`
	OSSConfigFetchStatus       string `json:"oss_config_fetch_status"`
	OSSConfigFetchError        string `json:"oss_config_fetch_error"`
	OSSConfigChanged           bool   `json:"oss_config_changed"`
	OSSConfigPreviousRecordID  int64  `json:"oss_config_previous_record_id,omitempty"`
	OSSConfigPreviousSHA256    string `json:"oss_config_previous_sha256,omitempty"`
	OSSConfigPreviousCreatedAt string `json:"oss_config_previous_created_at,omitempty"`
	RecordDeleted              bool   `json:"record_deleted"`
	BoundAt                    string `json:"bound_at"`
	FinishedAt                 string `json:"finished_at"`
	CreatedAt                  string `json:"created_at"`
	UpdatedAt                  string `json:"updated_at"`
}

type remoteOSSConfigSource struct {
	Name          string
	URL           string
	EncryptionKey string
}

type BuildRecordOSSVersion struct {
	RecordID      int64  `json:"record_id"`
	CodeID        int    `json:"code_id"`
	CodeName      string `json:"code_name"`
	CreatedAt     string `json:"created_at"`
	Content       string `json:"content"`
	ContentSHA256 string `json:"sha256"`
	ContentFormat string `json:"format"`
	SourceName    string `json:"source_name"`
	URL           string `json:"url"`
	FetchStatus   string `json:"fetch_status"`
}

func buildRecordAuditSnapshot(client, profileContent, profileBlobSHA, ossConfigContent, ossConfigContentFormat string) (BuildRecordAudit, error) {
	ossConfigContent = strings.TrimSpace(ossConfigContent)
	if len([]byte(ossConfigContent)) > maxBuildAuditOSSConfigContentBytes {
		return BuildRecordAudit{}, fmt.Errorf("OSS 配置内容过大，不能超过 %d 字节", maxBuildAuditOSSConfigContentBytes)
	}

	doc, err := parseProfileYamlDocument(profileContent)
	if err != nil {
		return BuildRecordAudit{}, fmt.Errorf("解析配置档案失败: %w", err)
	}
	root := ensureDocumentMappingNode(doc)
	profileRootKey := "xboard"
	if normalizeBuildClient(client) == buildClientNexGenReact {
		profileRootKey = "nexgen"
	}
	profileRoot := getMapValueNode(root, profileRootKey)
	if profileRoot == nil {
		return BuildRecordAudit{}, fmt.Errorf("配置档案缺少 %s 节点", profileRootKey)
	}

	remoteConfigNode := getMapValueNode(profileRoot, "remote_config")
	if remoteConfigNode == nil {
		remoteConfigNode = getMapValueNode(profileRoot, "remoteConfig")
	}
	remoteConfig := map[string]interface{}{}
	if remoteConfigNode != nil {
		if err := remoteConfigNode.Decode(&remoteConfig); err != nil {
			return BuildRecordAudit{}, fmt.Errorf("解析 remote_config 失败: %w", err)
		}
		if remoteConfig == nil {
			remoteConfig = map[string]interface{}{}
		}
	}
	ossConfigSources, err := findRemoteOSSConfigSources(remoteConfig)
	if err != nil {
		return BuildRecordAudit{}, err
	}
	ossConfigFetchStatus := "not_configured"
	ossConfigFetchError := ""
	ossConfigSourceName := ""
	ossConfigURL := ""
	if len(ossConfigSources) > 0 {
		ossConfigSourceName = ossConfigSources[0].Name
		ossConfigURL = ossConfigSources[0].URL
		fetchErrors := make([]string, 0, len(ossConfigSources))
		fetchSucceeded := false
		ossConfigContent = ""
		ossConfigContentFormat = ""
		for _, source := range ossConfigSources {
			fetchedContent, fetchedContentFormat, fetchedStatus, fetchErr := fetchRemoteOSSConfigContent(source.URL, source.EncryptionKey)
			if fetchErr != nil {
				fetchErrors = append(fetchErrors, source.URL+": "+fetchErr.Error())
				continue
			}
			ossConfigContent = fetchedContent
			ossConfigContentFormat = fetchedContentFormat
			ossConfigFetchStatus = fetchedStatus
			ossConfigSourceName = source.Name
			ossConfigURL = source.URL
			fetchSucceeded = true
			break
		}
		if !fetchSucceeded {
			ossConfigFetchStatus = "fetch_failed"
			ossConfigFetchError = strings.Join(fetchErrors, "；")
		}
	} else if ossConfigContent != "" {
		ossConfigFetchStatus = "client_submitted"
	}

	appTitle := strings.TrimSpace(readMapStringValue(profileRoot, "title"))
	if appTitle == "" {
		appTitle = strings.TrimSpace(readMapStringValue(getMapValueNode(profileRoot, "app"), "title"))
	}
	snapshot, err := json.Marshal(map[string]interface{}{
		"client":        normalizeBuildClient(client),
		"provider":      strings.TrimSpace(readMapStringValue(profileRoot, "provider")),
		"app_title":     appTitle,
		"remote_config": remoteConfig,
	})
	if err != nil {
		return BuildRecordAudit{}, fmt.Errorf("序列化 remote_config 快照失败: %w", err)
	}

	ossConfigContentFormat = strings.TrimSpace(ossConfigContentFormat)
	if ossConfigContent != "" && ossConfigContentFormat == "" {
		if json.Valid([]byte(ossConfigContent)) {
			ossConfigContentFormat = "json"
		} else {
			ossConfigContentFormat = "opaque"
		}
	}

	return BuildRecordAudit{
		ProfileBlobSHA:             strings.TrimSpace(profileBlobSHA),
		ProfileContentSHA256:       sha256Hex(profileContent),
		RemoteConfigSnapshot:       string(snapshot),
		RemoteConfigSnapshotSHA256: sha256Hex(string(snapshot)),
		OSSConfigContent:           ossConfigContent,
		OSSConfigContentSHA256:     sha256HexIfNotEmpty(ossConfigContent),
		OSSConfigContentFormat:     ossConfigContentFormat,
		OSSConfigSourceName:        ossConfigSourceName,
		OSSConfigURL:               ossConfigURL,
		OSSConfigFetchStatus:       ossConfigFetchStatus,
		OSSConfigFetchError:        ossConfigFetchError,
	}, nil
}

func findRemoteOSSConfigSources(remoteConfig map[string]interface{}) ([]remoteOSSConfigSource, error) {
	if remoteConfig == nil {
		return nil, nil
	}
	rawSources, ok := remoteConfig["sources"]
	if !ok || rawSources == nil {
		return nil, nil
	}
	sources, ok := rawSources.([]interface{})
	if !ok {
		return nil, fmt.Errorf("remote_config.sources 格式无效")
	}
	result := make([]remoteOSSConfigSource, 0, len(sources))
	for _, rawSource := range sources {
		source, ok := rawSource.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := source["name"].(string)
		if normalizeProfileSourceName(name) == "local" {
			continue
		}
		sourceURL, _ := source["url"].(string)
		sourceURL = strings.TrimSpace(sourceURL)
		if sourceURL != "" {
			encryptionKey, _ := source["encryption_key"].(string)
			result = append(result, remoteOSSConfigSource{
				Name:          normalizeProfileSourceName(name),
				URL:           sourceURL,
				EncryptionKey: strings.TrimSpace(encryptionKey),
			})
		}
	}
	return result, nil
}

func fetchRemoteOSSConfigContent(rawURL, encryptionKey string) (string, string, string, error) {
	parsedURL, err := validateRemoteOSSURL(rawURL)
	if err != nil {
		return "", "", "", err
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return "", "", "", fmt.Errorf("创建远程 OSS 请求失败: %w", err)
	}
	request.Header.Set("User-Agent", "Xboard-Mihomo-Build-Audit/1.0")
	response, err := remoteOSSHTTPClient.Do(request)
	if err != nil {
		return "", "", "", fmt.Errorf("读取远程 OSS 配置失败: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", "", "", fmt.Errorf("读取远程 OSS 配置失败: HTTP %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBuildAuditOSSConfigContentBytes+1))
	if err != nil {
		return "", "", "", fmt.Errorf("读取远程 OSS 配置失败: %w", err)
	}
	if len(body) > maxBuildAuditOSSConfigContentBytes {
		return "", "", "", fmt.Errorf("OSS 配置内容过大，不能超过 %d 字节", maxBuildAuditOSSConfigContentBytes)
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", "", "", fmt.Errorf("远程 OSS 配置内容为空")
	}

	if strings.TrimSpace(encryptionKey) == "" {
		return string(body), detectOSSConfigContentFormat(string(body)), "plaintext", nil
	}
	decryptedContent, err := decryptRemoteOSSConfigContent(string(body), encryptionKey)
	if err != nil {
		return "", "", "", err
	}
	return decryptedContent, detectOSSConfigContentFormat(decryptedContent), "decrypted", nil
}

func decryptRemoteOSSConfigContent(encodedContent, encodedKey string) (string, error) {
	key, err := decodeRemoteOSSBase64(encodedKey)
	if err != nil || len(key) != 32 {
		return "", fmt.Errorf("远程 OSS 加密密钥无效")
	}
	encryptedContent, err := decodeRemoteOSSBase64(encodedContent)
	if err != nil {
		return "", fmt.Errorf("远程 OSS 加密内容不是有效 Base64")
	}
	const nonceSize = 16
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建远程 OSS 解密器失败: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		return "", fmt.Errorf("创建远程 OSS 解密器失败: %w", err)
	}
	if len(encryptedContent) <= nonceSize+gcm.Overhead() {
		return "", fmt.Errorf("远程 OSS 加密内容长度无效")
	}
	plaintext, err := gcm.Open(nil, encryptedContent[:nonceSize], encryptedContent[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("远程 OSS 解密失败")
	}
	if strings.TrimSpace(string(plaintext)) == "" {
		return "", fmt.Errorf("远程 OSS 解密后的内容为空")
	}
	return string(plaintext), nil
}

func decodeRemoteOSSBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("Base64 解码失败")
}

func validateRemoteOSSURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsedURL == nil {
		return nil, fmt.Errorf("远程 OSS 地址无效")
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("远程 OSS 地址只支持 HTTP 或 HTTPS")
	}
	if parsedURL.Hostname() == "" || parsedURL.User != nil || parsedURL.Fragment != "" {
		return nil, fmt.Errorf("远程 OSS 地址无效")
	}
	if ip := net.ParseIP(parsedURL.Hostname()); ip != nil && isRestrictedRemoteOSSIP(ip) {
		return nil, fmt.Errorf("远程 OSS 地址不能指向内网或本机地址")
	}
	return parsedURL, nil
}

func newRemoteOSSHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialRemoteOSSContext(ctx, network, address)
		},
	}
	return &http.Client{
		Timeout:   buildAuditRemoteOSSFetchTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			_, err := validateRemoteOSSURL(req.URL.String())
			return err
		},
	}
}

func dialRemoteOSSContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("远程 OSS 地址无效")
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("解析远程 OSS 地址失败: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("远程 OSS 地址没有可用 IP")
	}
	for _, ip := range ips {
		if isRestrictedRemoteOSSIP(ip) {
			return nil, fmt.Errorf("远程 OSS 地址不能指向内网或本机地址")
		}
	}

	dialer := &net.Dialer{}
	var lastErr error
	for _, ip := range ips {
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("连接远程 OSS 失败: %w", lastErr)
}

func isRestrictedRemoteOSSIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func detectOSSConfigContentFormat(content string) string {
	trimmedContent := strings.TrimSpace(content)
	if json.Valid([]byte(trimmedContent)) {
		return "json"
	}
	return "plaintext"
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func sha256HexIfNotEmpty(value string) string {
	if value == "" {
		return ""
	}
	return sha256Hex(value)
}

func saveBuildRecordAudit(record *BuildRecord, snapshot BuildRecordAudit) error {
	if record == nil || record.ID <= 0 {
		return fmt.Errorf("打包记录无效")
	}

	audit := snapshot.withBuildRecord(record)
	if audit.RemoteConfigSnapshot == "" {
		audit.RemoteConfigSnapshot = "{}"
	}
	_, err := db.Exec(`
		INSERT INTO build_record_audits (
			record_id, code_id, code_name, request_id, client, profile, tag, branch, core, platforms,
			status, conclusion, run_id, run_url, profile_blob_sha, profile_content_sha256,
			remote_config_snapshot, remote_config_snapshot_sha256, oss_config_content,
			oss_config_content_sha256, oss_config_content_format, oss_config_source_name,
			oss_config_url, oss_config_fetch_status, oss_config_fetch_error, record_deleted, bound_at,
			finished_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
		ON CONFLICT(record_id) DO UPDATE SET
			code_id = excluded.code_id,
			code_name = excluded.code_name,
			request_id = excluded.request_id,
			client = excluded.client,
			profile = excluded.profile,
			tag = excluded.tag,
			branch = excluded.branch,
			core = excluded.core,
			platforms = excluded.platforms,
			status = excluded.status,
			conclusion = excluded.conclusion,
			run_id = excluded.run_id,
			run_url = excluded.run_url,
			profile_blob_sha = excluded.profile_blob_sha,
			profile_content_sha256 = excluded.profile_content_sha256,
			remote_config_snapshot = excluded.remote_config_snapshot,
			remote_config_snapshot_sha256 = excluded.remote_config_snapshot_sha256,
			oss_config_content = excluded.oss_config_content,
			oss_config_content_sha256 = excluded.oss_config_content_sha256,
			oss_config_content_format = excluded.oss_config_content_format,
				oss_config_source_name = excluded.oss_config_source_name,
				oss_config_url = excluded.oss_config_url,
				oss_config_fetch_status = excluded.oss_config_fetch_status,
				oss_config_fetch_error = excluded.oss_config_fetch_error,
				record_deleted = 0,
			bound_at = excluded.bound_at,
			finished_at = excluded.finished_at,
			created_at = excluded.created_at,
			updated_at = excluded.updated_at
	`,
		audit.RecordID,
		audit.CodeID,
		audit.CodeName,
		audit.RequestID,
		audit.Client,
		audit.Profile,
		audit.Tag,
		audit.Branch,
		audit.Core,
		audit.Platforms,
		audit.Status,
		audit.Conclusion,
		audit.RunID,
		audit.RunURL,
		audit.ProfileBlobSHA,
		audit.ProfileContentSHA256,
		audit.RemoteConfigSnapshot,
		audit.RemoteConfigSnapshotSHA256,
		audit.OSSConfigContent,
		audit.OSSConfigContentSHA256,
		audit.OSSConfigContentFormat,
		audit.OSSConfigSourceName,
		audit.OSSConfigURL,
		audit.OSSConfigFetchStatus,
		audit.OSSConfigFetchError,
		audit.BoundAt,
		audit.FinishedAt,
		audit.CreatedAt,
		audit.UpdatedAt,
	)
	return err
}

type buildRecordAuditScanner interface {
	Scan(dest ...interface{}) error
}

func scanBuildRecordAudit(scanner buildRecordAuditScanner) (BuildRecordAudit, error) {
	var audit BuildRecordAudit
	var boundAt, finishedAt sql.NullString
	if err := scanner.Scan(
		&audit.RecordID,
		&audit.CodeID,
		&audit.CodeName,
		&audit.RequestID,
		&audit.Client,
		&audit.Profile,
		&audit.Tag,
		&audit.Branch,
		&audit.Core,
		&audit.Platforms,
		&audit.Status,
		&audit.Conclusion,
		&audit.RunID,
		&audit.RunURL,
		&audit.ProfileBlobSHA,
		&audit.ProfileContentSHA256,
		&audit.RemoteConfigSnapshot,
		&audit.RemoteConfigSnapshotSHA256,
		&audit.OSSConfigContent,
		&audit.OSSConfigContentSHA256,
		&audit.OSSConfigContentFormat,
		&audit.OSSConfigSourceName,
		&audit.OSSConfigURL,
		&audit.OSSConfigFetchStatus,
		&audit.OSSConfigFetchError,
		&audit.RecordDeleted,
		&boundAt,
		&finishedAt,
		&audit.CreatedAt,
		&audit.UpdatedAt,
	); err != nil {
		return BuildRecordAudit{}, err
	}
	if boundAt.Valid {
		audit.BoundAt = boundAt.String
	}
	if finishedAt.Valid {
		audit.FinishedAt = finishedAt.String
	}
	audit.Client = normalizeBuildClient(audit.Client)
	audit.Core = normalizeBuildCore(audit.Core)
	if strings.TrimSpace(audit.OSSConfigContentSHA256) == "" && strings.TrimSpace(audit.OSSConfigContent) != "" {
		audit.OSSConfigContentSHA256 = sha256Hex(audit.OSSConfigContent)
	}
	return audit, nil
}

func isComparableBuildRecordOSS(audit BuildRecordAudit) bool {
	status := strings.ToLower(strings.TrimSpace(audit.OSSConfigFetchStatus))
	return strings.TrimSpace(audit.OSSConfigURL) != "" &&
		strings.TrimSpace(audit.OSSConfigContent) != "" &&
		status != "fetch_failed" &&
		status != "not_configured"
}

func buildAuditPanelsURLFingerprint(content string) (string, bool) {
	var document interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &document); err != nil {
		return "", false
	}
	root, ok := document.(map[string]interface{})
	if !ok {
		return "", false
	}
	rawPanels, ok := root["panels"]
	if !ok {
		return "", false
	}
	if _, ok := rawPanels.(map[string]interface{}); !ok {
		return "", false
	}

	urls := make([]string, 0)
	collectBuildAuditPanelURLs(rawPanels, &urls)
	sort.Strings(urls)
	uniqueURLs := urls[:0]
	for _, panelURL := range urls {
		if len(uniqueURLs) == 0 || uniqueURLs[len(uniqueURLs)-1] != panelURL {
			uniqueURLs = append(uniqueURLs, panelURL)
		}
	}
	fingerprint, err := json.Marshal(uniqueURLs)
	if err != nil {
		return "", false
	}
	return string(fingerprint), true
}

func collectBuildAuditPanelURLs(value interface{}, urls *[]string) {
	switch node := value.(type) {
	case []interface{}:
		for _, item := range node {
			collectBuildAuditPanelURLs(item, urls)
		}
	case map[string]interface{}:
		for _, key := range []string{"url", "website_url"} {
			if rawURL, ok := node[key].(string); ok {
				panelURL := strings.TrimSpace(rawURL)
				if panelURL != "" {
					*urls = append(*urls, panelURL)
				}
			}
		}
		for key, child := range node {
			if key == "url" || key == "website_url" {
				continue
			}
			collectBuildAuditPanelURLs(child, urls)
		}
	}
}

func findPreviousBuildRecordOSSVersion(audit BuildRecordAudit) (*BuildRecordOSSVersion, error) {
	if !isComparableBuildRecordOSS(audit) {
		return nil, nil
	}

	query := `SELECT record_id, code_id, code_name, COALESCE(created_at, ''),
		COALESCE(oss_config_content, ''), COALESCE(oss_config_content_sha256, ''),
		COALESCE(oss_config_content_format, ''), COALESCE(oss_config_source_name, ''),
		COALESCE(oss_config_url, ''), COALESCE(oss_config_fetch_status, '')
		FROM build_record_audits
		WHERE code_id = ?
		  AND TRIM(COALESCE(oss_config_url, '')) = ?
		  AND TRIM(COALESCE(oss_config_content, '')) <> ''
		  AND LOWER(TRIM(COALESCE(oss_config_fetch_status, ''))) NOT IN ('fetch_failed', 'not_configured')`
	args := []interface{}{audit.CodeID, strings.TrimSpace(audit.OSSConfigURL)}
	if strings.TrimSpace(audit.CreatedAt) == "" {
		query += " AND record_id < ?"
		args = append(args, audit.RecordID)
	} else {
		query += ` AND (
			datetime(COALESCE(created_at, '')) < datetime(?)
			OR (datetime(COALESCE(created_at, '')) = datetime(?) AND record_id < ?)
		)`
		args = append(args, audit.CreatedAt, audit.CreatedAt, audit.RecordID)
	}
	query += " ORDER BY datetime(COALESCE(created_at, '')) DESC, record_id DESC LIMIT 1"

	var version BuildRecordOSSVersion
	err := db.QueryRow(query, args...).Scan(
		&version.RecordID,
		&version.CodeID,
		&version.CodeName,
		&version.CreatedAt,
		&version.Content,
		&version.ContentSHA256,
		&version.ContentFormat,
		&version.SourceName,
		&version.URL,
		&version.FetchStatus,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(version.ContentSHA256) == "" && strings.TrimSpace(version.Content) != "" {
		version.ContentSHA256 = sha256Hex(version.Content)
	}
	return &version, nil
}

func annotateBuildRecordAuditChanges(audits []BuildRecordAudit) error {
	for index := range audits {
		audit := &audits[index]
		audit.OSSConfigChanged = false
		audit.OSSConfigPreviousRecordID = 0
		audit.OSSConfigPreviousSHA256 = ""
		audit.OSSConfigPreviousCreatedAt = ""
		if strings.TrimSpace(audit.OSSConfigContentSHA256) == "" && strings.TrimSpace(audit.OSSConfigContent) != "" {
			audit.OSSConfigContentSHA256 = sha256Hex(audit.OSSConfigContent)
		}
		previous, err := findPreviousBuildRecordOSSVersion(*audit)
		if err != nil {
			return err
		}
		if previous == nil {
			continue
		}
		audit.OSSConfigPreviousRecordID = previous.RecordID
		audit.OSSConfigPreviousSHA256 = previous.ContentSHA256
		audit.OSSConfigPreviousCreatedAt = previous.CreatedAt
		currentPanels, currentComparable := buildAuditPanelsURLFingerprint(audit.OSSConfigContent)
		previousPanels, previousComparable := buildAuditPanelsURLFingerprint(previous.Content)
		audit.OSSConfigChanged = currentComparable && previousComparable && currentPanels != previousPanels
	}
	return nil
}

func buildPreviousBuildRecordOSSContentSubquery(currentAlias string) string {
	return fmt.Sprintf(`(SELECT previous.oss_config_content
		FROM build_record_audits AS previous
		WHERE previous.code_id = %s.code_id
		  AND TRIM(COALESCE(previous.oss_config_url, '')) = TRIM(COALESCE(%s.oss_config_url, ''))
		  AND TRIM(COALESCE(previous.oss_config_url, '')) <> ''
		  AND TRIM(COALESCE(previous.oss_config_content, '')) <> ''
		  AND LOWER(TRIM(COALESCE(previous.oss_config_fetch_status, ''))) NOT IN ('fetch_failed', 'not_configured')
		  AND (
			datetime(COALESCE(previous.created_at, '')) < datetime(COALESCE(%s.created_at, ''))
			OR (datetime(COALESCE(previous.created_at, '')) = datetime(COALESCE(%s.created_at, '')) AND previous.record_id < %s.record_id)
		)
		ORDER BY datetime(COALESCE(previous.created_at, '')) DESC, previous.record_id DESC
		LIMIT 1)`, currentAlias, currentAlias, currentAlias, currentAlias, currentAlias)
}

func listBuildRecordAudits(codeID int, client string, limit int) ([]BuildRecordAudit, error) {
	return listBuildRecordAuditsWithOSSChangeFilter(codeID, client, limit, "")
}

func listBuildRecordAuditsWithOSSChangeFilter(codeID int, client string, limit int, ossChange string) ([]BuildRecordAudit, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	query := `SELECT record_id, code_id, code_name, request_id, client, profile, tag, branch, core, platforms,
		status, conclusion, COALESCE(run_id, 0), COALESCE(run_url, ''), COALESCE(profile_blob_sha, ''),
		COALESCE(profile_content_sha256, ''), COALESCE(remote_config_snapshot, '{}'),
		COALESCE(remote_config_snapshot_sha256, ''), COALESCE(oss_config_content, ''),
		COALESCE(oss_config_content_sha256, ''), COALESCE(oss_config_content_format, ''),
		COALESCE(oss_config_source_name, ''), COALESCE(oss_config_url, ''),
		COALESCE(oss_config_fetch_status, ''), COALESCE(oss_config_fetch_error, ''),
		COALESCE(record_deleted, 0), bound_at, finished_at, created_at, updated_at
		FROM build_record_audits AS current`
	args := []interface{}{}
	whereParts := []string{}
	if codeID > 0 {
		whereParts = append(whereParts, "current.code_id = ?")
		args = append(args, codeID)
	}
	if strings.TrimSpace(client) != "" {
		whereParts = append(whereParts, "current.client = ?")
		args = append(args, normalizeBuildClient(client))
	}
	if strings.EqualFold(strings.TrimSpace(ossChange), "changed") {
		previousContent := buildPreviousBuildRecordOSSContentSubquery("current")
		whereParts = append(whereParts,
			"TRIM(COALESCE(current.oss_config_url, '')) <> '' AND "+
				"TRIM(COALESCE(current.oss_config_content, '')) <> '' AND "+
				"LOWER(TRIM(COALESCE(current.oss_config_fetch_status, ''))) NOT IN ('fetch_failed', 'not_configured') AND "+
				previousContent+" IS NOT NULL AND "+
				"TRIM(COALESCE("+previousContent+", '')) <> TRIM(COALESCE(current.oss_config_content, ''))")
	}
	if len(whereParts) > 0 {
		query += " WHERE " + strings.Join(whereParts, " AND ")
	}
	query += " ORDER BY current.created_at DESC, current.record_id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	audits := []BuildRecordAudit{}
	for rows.Next() {
		audit, err := scanBuildRecordAudit(rows)
		if err != nil {
			continue
		}
		audits = append(audits, audit)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := annotateBuildRecordAuditChanges(audits); err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(ossChange), "changed") {
		filtered := audits[:0]
		for _, audit := range audits {
			if audit.OSSConfigChanged {
				filtered = append(filtered, audit)
			}
		}
		audits = filtered
	}
	return audits, nil
}

func getBuildRecordOSSVersion(recordID int64) (*BuildRecordOSSVersion, error) {
	if recordID <= 0 {
		return nil, nil
	}
	var version BuildRecordOSSVersion
	err := db.QueryRow(`
		SELECT record_id, code_id, code_name, COALESCE(created_at, ''),
			COALESCE(oss_config_content, ''), COALESCE(oss_config_content_sha256, ''),
			COALESCE(oss_config_content_format, ''), COALESCE(oss_config_source_name, ''),
			COALESCE(oss_config_url, ''), COALESCE(oss_config_fetch_status, '')
		FROM build_record_audits
		WHERE record_id = ?
	`, recordID).Scan(
		&version.RecordID,
		&version.CodeID,
		&version.CodeName,
		&version.CreatedAt,
		&version.Content,
		&version.ContentSHA256,
		&version.ContentFormat,
		&version.SourceName,
		&version.URL,
		&version.FetchStatus,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(version.ContentSHA256) == "" && strings.TrimSpace(version.Content) != "" {
		version.ContentSHA256 = sha256Hex(version.Content)
	}
	return &version, nil
}

func updateBuildRecordAuditStatus(recordID, runID int64, status, conclusion, runURL string) error {
	if recordID <= 0 {
		return nil
	}
	_, err := db.Exec(`
		UPDATE build_record_audits
		SET run_id = CASE WHEN ? > 0 THEN ? ELSE run_id END,
			run_url = CASE WHEN ? != '' THEN ? ELSE run_url END,
			status = CASE WHEN ? != '' THEN ? ELSE status END,
			conclusion = ?,
			bound_at = CASE WHEN ? > 0 AND (bound_at IS NULL OR bound_at = '') THEN CURRENT_TIMESTAMP ELSE bound_at END,
			finished_at = CASE WHEN ? = 'completed' THEN CURRENT_TIMESTAMP ELSE finished_at END,
			updated_at = CURRENT_TIMESTAMP
		WHERE record_id = ?
	`, runID, runID, runURL, runURL, status, status, conclusion, runID, status, recordID)
	return err
}

func markBuildRecordAuditDeleted(recordID int64) error {
	if recordID <= 0 {
		return nil
	}
	_, err := db.Exec(`
		UPDATE build_record_audits
		SET record_deleted = 1, updated_at = CURRENT_TIMESTAMP
		WHERE record_id = ?
	`, recordID)
	return err
}

func (audit BuildRecordAudit) withBuildRecord(record *BuildRecord) BuildRecordAudit {
	if record == nil {
		return audit
	}
	audit.RecordID = record.ID
	audit.CodeID = record.CodeID
	audit.CodeName = record.CodeName
	audit.RequestID = buildRecordRequestID(record)
	audit.Client = normalizeBuildClient(record.Client)
	audit.Profile = record.Profile
	audit.Tag = record.Tag
	audit.Branch = record.Branch
	audit.Core = normalizeBuildCore(record.Core)
	audit.Platforms = record.Platforms
	audit.Status = record.Status
	audit.Conclusion = record.Conclusion
	audit.RunID = record.RunID
	audit.RunURL = record.RunURL
	audit.BoundAt = record.BoundAt
	audit.FinishedAt = record.FinishedAt
	audit.CreatedAt = record.CreatedAt
	audit.UpdatedAt = record.UpdatedAt
	return audit
}
