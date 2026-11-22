package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
)

type databaseSnapshot struct {
	SHA256 string           `json:"sha256"`
	Tables map[string]int64 `json:"tables"`
}

func sqliteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func inspectDatabase(database *sql.DB) (databaseSnapshot, error) {
	snapshot := databaseSnapshot{Tables: map[string]int64{}}
	tx, err := database.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return snapshot, err
	}
	defer tx.Rollback()
	var integrity string
	if err := tx.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil {
		return snapshot, err
	}
	if integrity != "ok" {
		return snapshot, fmt.Errorf("数据库完整性检查未通过")
	}
	hash := sha256.New()
	encoder := json.NewEncoder(hash)
	rows, err := tx.Query("SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema ORDER BY type, name")
	if err != nil {
		return snapshot, err
	}
	var tables []string
	for rows.Next() {
		var item [4]string
		if err := rows.Scan(&item[0], &item[1], &item[2], &item[3]); err != nil {
			rows.Close()
			return snapshot, err
		}
		encoder.Encode(item)
		if item[0] == "table" {
			tables = append(tables, item[1])
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return snapshot, err
	}
	rows.Close()
	for _, table := range tables {
		rows, err := tx.Query("SELECT * FROM " + sqliteIdentifier(table) + " LIMIT 0")
		if err != nil {
			return snapshot, err
		}
		columns, err := rows.Columns()
		rows.Close()
		if err != nil {
			return snapshot, err
		}
		var expressions []string
		for _, column := range columns {
			name := sqliteIdentifier(column)
			expressions = append(expressions, "typeof("+name+")", "quote("+name+")")
		}
		rows, err = tx.Query("SELECT " + strings.Join(expressions, ",") + " FROM " + sqliteIdentifier(table))
		if err != nil {
			return snapshot, err
		}
		// 对 SQL 原始值求摘要，避免日期和布尔值的驱动转换影响核对。
		var records []string
		for rows.Next() {
			values := make([]string, len(expressions))
			pointers := make([]any, len(values))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				return snapshot, err
			}
			record, _ := json.Marshal(values)
			records = append(records, string(record))
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return snapshot, err
		}
		rows.Close()
		sort.Strings(records)
		encoder.Encode(table)
		encoder.Encode(columns)
		for _, record := range records {
			encoder.Encode(record)
		}
		snapshot.Tables[table] = int64(len(records))
	}
	snapshot.SHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	return snapshot, tx.Commit()
}

func encryptPlainDatabase(source, target string) (snapshot databaseSnapshot, err error) {
	file, err := os.Open(source)
	if err != nil {
		return snapshot, err
	}
	var header [16]byte
	_, err = io.ReadFull(file, header[:])
	file.Close()
	if err != nil || string(header[:]) != "SQLite format 3\x00" {
		return snapshot, fmt.Errorf("源文件必须是现有明文 SQLite 数据库")
	}
	key, err := databaseEncryptionKey()
	if err != nil {
		return snapshot, err
	}
	// 目标必须是新文件，禁止覆盖原库或已有备份。
	file, err = os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return snapshot, err
	}
	file.Close()
	defer func() {
		if err != nil {
			for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
				os.Remove(target + suffix)
			}
		}
	}()
	sourceURI, err := databaseURI(source, "ro", "")
	if err != nil {
		return snapshot, err
	}
	plain, err := driver.Open(sourceURI)
	if err != nil {
		return snapshot, err
	}
	defer plain.Close()
	before, err := inspectDatabase(plain)
	if err != nil {
		return snapshot, err
	}
	targetURI, err := databaseURI(target, "rw", "xts")
	if err != nil {
		return snapshot, err
	}
	conn, err := sqlite3.Open(targetURI)
	if err != nil {
		return snapshot, err
	}
	defer conn.Close()
	if err = conn.Exec("PRAGMA hexkey='" + key + "'"); err != nil {
		return snapshot, fmt.Errorf("设置迁移目标密钥失败")
	}
	if err = conn.Restore("main", sourceURI); err != nil {
		return snapshot, err
	}
	if err = conn.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		return snapshot, err
	}
	if err = conn.Close(); err != nil {
		return snapshot, err
	}
	encrypted, err := openEncryptedDatabase(target, "ro")
	if err != nil {
		return snapshot, err
	}
	defer encrypted.Close()
	snapshot, err = inspectDatabase(encrypted)
	if err != nil {
		return snapshot, err
	}
	after, err := inspectDatabase(plain)
	if err != nil {
		return snapshot, err
	}
	if before.SHA256 != snapshot.SHA256 || before.SHA256 != after.SHA256 {
		return snapshot, fmt.Errorf("迁移前后数据不一致或源数据库仍在写入，原库已保留")
	}
	return snapshot, nil
}

func runDatabaseCommand(args []string) error {
	var snapshot databaseSnapshot
	var err error
	switch {
	case len(args) == 3 && args[0] == "--encrypt-database":
		snapshot, err = encryptPlainDatabase(args[1], args[2])
	case len(args) == 2 && args[0] == "--check-database":
		var database *sql.DB
		database, err = openEncryptedDatabase(args[1], "ro")
		if err == nil {
			defer database.Close()
			snapshot, err = inspectDatabase(database)
		}
	default:
		return fmt.Errorf("用法：--encrypt-database 原库 新加密库；或 --check-database 加密库")
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(snapshot)
}
