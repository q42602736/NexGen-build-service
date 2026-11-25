package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	androidSigningModeLegacy        = "legacy"
	androidSigningModeProfile       = "profile"
	androidSigningLocalDir          = "data/android-signing"
	androidSigningCryptoVersion     = "v1"
	androidSigningLocalAADPrefix    = "nexgen-android-signing-local-v1:"
	androidSigningDispatchAADPrefix = "nexgen-android-signing-dispatch-v1:"
	androidSigningCertValidityYears = 30
)

type ProfileAndroidSigningRecord struct {
	Client           string
	ProfileName      string
	SigningID        string
	Enabled          bool
	BrandName        string
	Subject          string
	KeyAlias         string
	CertSHA256       string
	CertSHA1         string
	SerialHex        string
	NotBefore        string
	NotAfter         string
	LocalFilePath    string
	EncryptedPayload string
	CreatedAt        string
	UpdatedAt        string
}

type ProfileAndroidSigningSummary struct {
	Enabled         bool   `json:"enabled"`
	HasCert         bool   `json:"has_cert"`
	SigningID       string `json:"signing_id,omitempty"`
	BrandName       string `json:"brand_name,omitempty"`
	Subject         string `json:"subject,omitempty"`
	KeyAlias        string `json:"key_alias,omitempty"`
	CertSHA256      string `json:"cert_sha256,omitempty"`
	CertSHA1        string `json:"cert_sha1,omitempty"`
	SerialHex       string `json:"serial_hex,omitempty"`
	NotBefore       string `json:"not_before,omitempty"`
	NotAfter        string `json:"not_after,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	LocalFilePath   string `json:"local_file_path,omitempty"`
	EncryptionReady bool   `json:"encryption_ready"`
}

type androidSigningPlainBundle struct {
	Version        int    `json:"version"`
	SigningID      string `json:"signing_id"`
	ProfileKey     string `json:"profile_key"`
	BrandName      string `json:"brand_name"`
	KeyAlias       string `json:"key_alias"`
	Subject        string `json:"subject"`
	CertSHA256     string `json:"cert_sha256"`
	CertSHA1       string `json:"cert_sha1"`
	SerialHex      string `json:"serial_hex"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	CertificatePEM string `json:"certificate_pem"`
}

func deriveLocalAndroidSigningAESKey() ([]byte, error) {
	dbKeyHex, err := databaseEncryptionKey()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(dbKeyHex))
	mac.Write([]byte("nexgen-local-android-signing-key-v1"))
	return mac.Sum(nil), nil
}

func deriveDispatchTransportAESKey(sourceToken, requestID string) []byte {
	sum := sha256.Sum256([]byte("nexgen-dispatch-v1:" + strings.TrimSpace(sourceToken) + ":" + strings.TrimSpace(requestID)))
	return sum[:]
}

func encryptAndroidSigningEnvelope(aesKey []byte, aadPrefix, contextID string, plain []byte) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("初始化加密器失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("初始化 GCM 失败: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("生成加密随机数失败: %w", err)
	}
	aad := []byte(aadPrefix + contextID)
	sealed := gcm.Seal(nil, nonce, plain, aad)
	tagStart := len(sealed) - gcm.Overhead()
	ciphertext := sealed[:tagStart]
	tag := sealed[tagStart:]

	return fmt.Sprintf(
		"%s:%s:%s:%s:%s",
		androidSigningCryptoVersion,
		contextID,
		base64.StdEncoding.EncodeToString(nonce),
		base64.StdEncoding.EncodeToString(tag),
		base64.StdEncoding.EncodeToString(ciphertext),
	), nil
}

func decryptAndroidSigningEnvelope(aesKey []byte, aadPrefix, envelope string) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(envelope), ":")
	if len(parts) != 5 || parts[0] != androidSigningCryptoVersion {
		return nil, fmt.Errorf("本地加密证书格式无效")
	}
	contextID := parts[1]
	nonce, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("解析证书随机数失败: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("解析证书校验标签失败: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("解析证书密文失败: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("初始化解密器失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM 失败: %w", err)
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	aad := []byte(aadPrefix + contextID)
	plain, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("解密本地安卓证书失败，请核对 DATABASE_ENCRYPTION_KEY 是否与生成时一致")
	}
	return plain, nil
}

func resolveAndroidSigningBrandName(profileName, yamlContent string) string {
	brand := strings.TrimSpace(profileDisplayNameFromYaml(yamlContent, ""))
	if brand == "" {
		brand = strings.TrimSpace(stripGeneratedProfileKeySuffix(profileName))
	}
	if brand == "" {
		brand = strings.TrimSpace(profileName)
	}
	// 去除控制字符并限制在 RFC 5280 CommonName 64 字符上限内。
	brand = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, brand))
	if brand == "" {
		return "Client"
	}
	runes := []rune(brand)
	if len(runes) > 64 {
		brand = strings.TrimSpace(string(runes[:64]))
	}
	if brand == "" {
		return "Client"
	}
	return brand
}

func generateProfileAndroidSigning(profileKey, brandName string) (*androidSigningPlainBundle, error) {
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("生成证书标识失败: %w", err)
	}
	signingID := hex.EncodeToString(idBytes)
	keyAlias := "brand_" + signingID[:8]

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成 RSA-2048 私钥失败: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 127)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("生成证书序列号失败: %w", err)
	}
	if serialNumber.Sign() <= 0 {
		serialNumber = big.NewInt(1)
	}

	now := time.Now().UTC()
	notBefore := now.Add(-5 * time.Minute).Truncate(time.Second)
	notAfter := now.AddDate(androidSigningCertValidityYears, 0, 0).Truncate(time.Second)

	subject := pkix.Name{
		Country:            []string{"CN"},
		Organization:       []string{brandName},
		OrganizationalUnit: []string{"Mobile"},
		CommonName:         brandName,
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("签发自签名证书失败: %w", err)
	}

	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("编码私钥失败: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Key,
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	sha256Sum := sha256.Sum256(certDER)
	sha1Sum := sha1.Sum(certDER)

	return &androidSigningPlainBundle{
		Version:        1,
		SigningID:      signingID,
		ProfileKey:     profileKey,
		BrandName:      brandName,
		KeyAlias:       keyAlias,
		Subject:        fmt.Sprintf("CN=%s, OU=Mobile, O=%s, C=CN", brandName, brandName),
		CertSHA256:     hex.EncodeToString(sha256Sum[:]),
		CertSHA1:       hex.EncodeToString(sha1Sum[:]),
		SerialHex:      strings.ToUpper(serialNumber.Text(16)),
		NotBefore:      notBefore.Format(time.RFC3339),
		NotAfter:       notAfter.Format(time.RFC3339),
		PrivateKeyPEM:  string(keyPEM),
		CertificatePEM: string(certPEM),
	}, nil
}

func localAndroidSigningFilePath(signingID string) string {
	return filepath.Join(androidSigningLocalDir, signingID+".enc")
}

func ensureLocalAndroidSigningFile(filePath, encryptedPayload string) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("创建本地证书目录失败: %w", err)
	}
	if existing, err := os.ReadFile(filePath); err == nil && strings.TrimSpace(string(existing)) != "" {
		return nil
	}
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(strings.TrimSpace(encryptedPayload)+"\n"), 0600); err != nil {
		return fmt.Errorf("写入本地加密证书文件失败: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("保存本地加密证书文件失败: %w", err)
	}
	return nil
}

func loadLocalAndroidSigningPlainJSON(rec *ProfileAndroidSigningRecord) ([]byte, error) {
	localKey, err := deriveLocalAndroidSigningAESKey()
	if err != nil {
		return nil, err
	}
	envelope := ""
	if rec.LocalFilePath != "" {
		if raw, readErr := os.ReadFile(rec.LocalFilePath); readErr == nil && strings.TrimSpace(string(raw)) != "" {
			envelope = strings.TrimSpace(string(raw))
		}
	}
	if envelope == "" && strings.TrimSpace(rec.EncryptedPayload) != "" {
		envelope = strings.TrimSpace(rec.EncryptedPayload)
		if rec.LocalFilePath != "" {
			_ = ensureLocalAndroidSigningFile(rec.LocalFilePath, envelope)
		}
	}
	if envelope == "" {
		return nil, fmt.Errorf("未找到本地加密证书内容")
	}
	return decryptAndroidSigningEnvelope(localKey, androidSigningLocalAADPrefix, envelope)
}

func sealAndroidSigningForDispatch(rec *ProfileAndroidSigningRecord, requestID string) (string, error) {
	plainJSON, err := loadLocalAndroidSigningPlainJSON(rec)
	if err != nil {
		return "", err
	}
	transportKey := deriveDispatchTransportAESKey(cfg.SourceToken, requestID)
	return encryptAndroidSigningEnvelope(transportKey, androidSigningDispatchAADPrefix, rec.SigningID, plainJSON)
}

func getProfileAndroidSigning(client, profileName string) (*ProfileAndroidSigningRecord, error) {
	client = normalizeBuildClient(client)
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return nil, nil
	}

	// 同档案在 Flutter 与 React 客户端共用同一把安卓签名证书：
	// 优先命中当前 client 记录，其次复用另一客户端已生成的同档案证书。
	var rec ProfileAndroidSigningRecord
	err := db.QueryRow(
		`SELECT client, profile_name, signing_id, enabled, brand_name, subject, key_alias,
		        cert_sha256, cert_sha1, serial_hex, not_before, not_after, bundle_path,
		        encrypted_payload, COALESCE(created_at, ''), COALESCE(updated_at, '')
		 FROM profile_android_signing
		 WHERE profile_name = ?
		 ORDER BY CASE WHEN client = ? THEN 0 ELSE 1 END, updated_at DESC
		 LIMIT 1`,
		profileName, client,
	).Scan(
		&rec.Client,
		&rec.ProfileName,
		&rec.SigningID,
		&rec.Enabled,
		&rec.BrandName,
		&rec.Subject,
		&rec.KeyAlias,
		&rec.CertSHA256,
		&rec.CertSHA1,
		&rec.SerialHex,
		&rec.NotBefore,
		&rec.NotAfter,
		&rec.LocalFilePath,
		&rec.EncryptedPayload,
		&rec.CreatedAt,
		&rec.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func getProfileAndroidSigningEnabledForClient(client, profileName string, rec *ProfileAndroidSigningRecord) bool {
	client = normalizeBuildClient(client)
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return false
	}

	var enabled bool
	err := db.QueryRow(
		`SELECT enabled
		 FROM profile_android_signing_client_state
		 WHERE client = ? AND profile_name = ?`,
		client, profileName,
	).Scan(&enabled)
	if err == nil {
		return enabled
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false
	}
	// 兼容升级前已有数据：原归属当前客户端的记录沿用其 enabled，另一客户端默认未开启。
	if rec != nil && normalizeBuildClient(rec.Client) == client {
		return rec.Enabled
	}
	return false
}

func upsertProfileAndroidSigning(rec *ProfileAndroidSigningRecord) error {
	_, err := db.Exec(
		`INSERT INTO profile_android_signing (
			client, profile_name, signing_id, enabled, brand_name, subject, key_alias,
			cert_sha256, cert_sha1, serial_hex, not_before, not_after, bundle_path,
			encrypted_payload
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(client, profile_name) DO UPDATE SET
			enabled = excluded.enabled,
			bundle_path = excluded.bundle_path,
			encrypted_payload = excluded.encrypted_payload,
			updated_at = CURRENT_TIMESTAMP`,
		normalizeBuildClient(rec.Client),
		strings.TrimSpace(rec.ProfileName),
		rec.SigningID,
		rec.Enabled,
		rec.BrandName,
		rec.Subject,
		rec.KeyAlias,
		rec.CertSHA256,
		rec.CertSHA1,
		rec.SerialHex,
		rec.NotBefore,
		rec.NotAfter,
		rec.LocalFilePath,
		rec.EncryptedPayload,
	)
	return err
}

func setProfileAndroidSigningEnabled(client, profileName string, enabled bool) error {
	client = normalizeBuildClient(client)
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return nil
	}
	if _, err := db.Exec(
		`INSERT INTO profile_android_signing_client_state (client, profile_name, enabled)
		 VALUES (?, ?, ?)
		 ON CONFLICT(client, profile_name) DO UPDATE SET
			enabled = excluded.enabled,
			updated_at = CURRENT_TIMESTAMP`,
		client, profileName, enabled,
	); err != nil {
		return err
	}
	_, err := db.Exec(
		`UPDATE profile_android_signing
		 SET enabled = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE client = ? AND profile_name = ?`,
		enabled,
		client,
		profileName,
	)
	return err
}

func buildProfileAndroidSigningSummary(client, profileName string) ProfileAndroidSigningSummary {
	_, err := deriveLocalAndroidSigningAESKey()
	summary := ProfileAndroidSigningSummary{
		EncryptionReady: err == nil,
	}
	rec, err := getProfileAndroidSigning(client, profileName)
	if err != nil || rec == nil {
		return summary
	}
	summary.Enabled = getProfileAndroidSigningEnabledForClient(client, profileName, rec)
	summary.HasCert = rec.SigningID != "" && rec.CertSHA256 != ""
	summary.SigningID = rec.SigningID
	summary.BrandName = rec.BrandName
	summary.Subject = rec.Subject
	summary.KeyAlias = rec.KeyAlias
	summary.CertSHA256 = rec.CertSHA256
	summary.CertSHA1 = rec.CertSHA1
	summary.SerialHex = rec.SerialHex
	summary.NotBefore = rec.NotBefore
	summary.NotAfter = rec.NotAfter
	summary.CreatedAt = rec.CreatedAt
	summary.LocalFilePath = rec.LocalFilePath
	return summary
}

func platformsIncludeAndroid(client, core, platforms string) bool {
	expanded, err := expandRequestedBuildPlatformsForClient(client, core, platforms)
	if err != nil {
		return false
	}
	for _, item := range expanded {
		if item == "android" || item == "android-tv" {
			return true
		}
	}
	return false
}

func (h *Handlers) ensureProfileAndroidSigningForBuild(client, profileName, yamlContent string) (*ProfileAndroidSigningRecord, int, error) {
	client = normalizeBuildClient(client)
	profileName = strings.TrimSpace(profileName)

	localKey, err := deriveLocalAndroidSigningAESKey()
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("本地加密密钥不可用: %w", err)
	}

	existing, err := getProfileAndroidSigning(client, profileName)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("读取档案安卓证书记录失败: %w", err)
	}
	if existing != nil && existing.SigningID != "" && existing.EncryptedPayload != "" {
		localPath := localAndroidSigningFilePath(existing.SigningID)
		if existing.LocalFilePath == "" || !strings.HasPrefix(existing.LocalFilePath, androidSigningLocalDir) {
			existing.LocalFilePath = localPath
		}
		if err := ensureLocalAndroidSigningFile(existing.LocalFilePath, existing.EncryptedPayload); err != nil {
			return nil, http.StatusInternalServerError, err
		}
		if err := setProfileAndroidSigningEnabled(client, profileName, true); err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("更新档案安卓证书状态失败: %w", err)
		}
		existing.Enabled = true
		return existing, http.StatusOK, nil
	}

	brandName := resolveAndroidSigningBrandName(profileName, yamlContent)
	bundle, err := generateProfileAndroidSigning(profileName, brandName)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	plainJSON, err := json.Marshal(bundle)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("序列化安卓证书数据失败: %w", err)
	}
	encryptedPayload, err := encryptAndroidSigningEnvelope(localKey, androidSigningLocalAADPrefix, bundle.SigningID, plainJSON)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	localPath := localAndroidSigningFilePath(bundle.SigningID)
	if err := ensureLocalAndroidSigningFile(localPath, encryptedPayload); err != nil {
		return nil, http.StatusInternalServerError, err
	}

	nowText := time.Now().UTC().Format("2006-01-02 15:04:05")
	rec := &ProfileAndroidSigningRecord{
		Client:           client,
		ProfileName:      profileName,
		SigningID:        bundle.SigningID,
		Enabled:          true,
		BrandName:        bundle.BrandName,
		Subject:          bundle.Subject,
		KeyAlias:         bundle.KeyAlias,
		CertSHA256:       bundle.CertSHA256,
		CertSHA1:         bundle.CertSHA1,
		SerialHex:        bundle.SerialHex,
		NotBefore:        bundle.NotBefore,
		NotAfter:         bundle.NotAfter,
		LocalFilePath:    localPath,
		EncryptedPayload: encryptedPayload,
		CreatedAt:        nowText,
		UpdatedAt:        nowText,
	}
	if err := upsertProfileAndroidSigning(rec); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("保存档案安卓证书记录失败: %w", err)
	}
	if err := setProfileAndroidSigningEnabled(client, profileName, true); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("保存客户端安卓证书启用状态失败: %w", err)
	}
	return rec, http.StatusOK, nil
}

func (h *Handlers) GetProfileAndroidSigning(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	claims := getClaims(r)
	client := normalizeBuildClient(r.URL.Query().Get("client"))

	if ok, message := canAccessClientForClaims(claims, client); !ok {
		jsonError(w, message, http.StatusForbidden)
		return
	}
	if !claims.canAccessProfile(name) {
		jsonError(w, "无权访问该档案", http.StatusForbidden)
		return
	}

	jsonResponse(w, buildProfileAndroidSigningSummary(client, name))
}
