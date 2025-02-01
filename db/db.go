package db

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq" // PostgreSQLドライバをインポート
)

// NewDB はデータベースに接続し、*sql.DBを返す
func NewDB() (*sql.DB, error) {
	// 環境変数からデータベース接続設定を取得
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")

	// データベース接続
	db, err := sql.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPass, dbName))
	if err != nil {
		return nil, err
	}

	// 接続確認
	err = db.Ping()
	if err != nil {
		return nil, err
	}
	fmt.Println("データベースに接続しました")

	return db, nil
}

// SaveRecord は学習記録をデータベースに保存する
func SaveRecord(db *sql.DB, date, startTime, endTime, category, userID string) error {
	// 学習記録をデータベースに保存
	_, err := db.Exec(
		`INSERT INTO study_records (study_date, study_start_time, study_end_time, category, user_id) VALUES ($1, $2, $3, $4, $5)`,
		date, startTime, endTime, category, userID)
	if err != nil {
		return err
	}

	fmt.Println("学習記録を保存しました:", date, startTime, endTime, category)
	return nil
}
