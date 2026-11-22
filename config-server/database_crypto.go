package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
	_ "github.com/ncruces/go-sqlite3/vfs/xts"
)

func databaseEncryptionKey() (string, error) {
	key := getEnv("DATABASE_ENCRYPTION_KEY", "")
	decoded, err := hex.DecodeString(key)
	if err != nil || len(decoded) != 64 {
		return "", fmt.Errorf("内置数据库密钥无效，请使用原密钥重新构建")
	}
	return key, nil
}

func databaseURI(path, mode, vfs string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	uri := url.URL{Scheme: "file", Path: absolute}
	params := url.Values{"mode": {mode}, "_timefmt": {"sqlite"}}
	if vfs != "" {
		params.Set("vfs", vfs)
	}
	uri.RawQuery = params.Encode()
	return uri.String(), nil
}

func openEncryptedDatabase(path, mode string) (*sql.DB, error) {
	key, err := databaseEncryptionKey()
	if err != nil {
		return nil, err
	}
	uri, err := databaseURI(path, mode, "xts")
	if err != nil {
		return nil, err
	}
	return driver.Open(uri, func(conn *sqlite3.Conn) error {
		// 每个连接先设置密钥，密钥不放入连接地址或日志。
		if err := conn.Exec("PRAGMA hexkey='" + key + "'"); err != nil {
			return fmt.Errorf("设置数据库密钥失败")
		}
		if err := conn.BusyTimeout(5 * time.Second); err != nil {
			return err
		}
		return conn.Exec("PRAGMA temp_store=MEMORY")
	})
}
