package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

func main() {
	if len(os.Args) != 4 {
		fail("请指定本地 .env、临时目录和源码目录")
	}
	source, work, root := os.Args[1], os.Args[2], os.Args[3]
	info, err := os.Stat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		fail("本地 .env 必须是仅允许所有者读写的普通文件（0600）")
	}
	values, err := godotenv.Read(source)
	if err != nil {
		// 解析错误可能包含原始配置行，禁止直接输出。
		fail("本地 .env 解析失败，请检查配置格式")
	}
	for _, key := range []string{"GITHUB_TOKEN", "GITHUB_OWNER", "GITHUB_REPO", "JWT_SECRET", "ADMIN_PASSWORD", "BUILD_EVENT_TOKEN", "GITHUB_WEBHOOK_SECRET", "SECURE_LOG_PRIVATE_KEY", "DATABASE_ENCRYPTION_KEY"} {
		if values[key] == "" {
			fail("本地 .env 缺少必需字段：" + key)
		}
	}
	key, err := hex.DecodeString(values["DATABASE_ENCRYPTION_KEY"])
	if err != nil || len(key) != 64 {
		fail("DATABASE_ENCRYPTION_KEY 必须是 128 位十六进制字符")
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.HasPrefix(key, "CF_WORKER_") {
			fail("本地 .env 仍包含已停用的 Worker 配置")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var code strings.Builder
	code.WriteString("package main\n\nvar embeddedEnvironment = map[string]string{\n")
	for _, key := range keys {
		fmt.Fprintf(&code, "\t%s: %s,\n", strconv.Quote(key), strconv.Quote(values[key]))
	}
	code.WriteString("}\n")
	replacement := filepath.Join(work, "embedded_config.go")
	if err := os.WriteFile(replacement, []byte(code.String()), 0600); err != nil {
		fail("无法写入私有临时配置")
	}
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(root, "embedded_config.go"): replacement}})
	if err != nil || os.WriteFile(filepath.Join(work, "overlay.json"), overlay, 0600) != nil {
		fail("无法生成临时构建映射")
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
