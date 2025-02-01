package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"gin-learning-record-management-app/db"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var (
	sessionKey = "loginUser" // セッションKey
)

func main() {
	// .envファイルを読み込む
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// データベース接続
	sqlDb, err := db.NewDB()
	if err != nil {
		panic(err)
	}
	defer sqlDb.Close()

	router := gin.Default()
	// CORSミドルウェアを設定
	secretKey := generateRandomKey(32) // 32バイトのランダムな値を設定
	store := cookie.NewStore([]byte(secretKey))

	router.Use(sessions.Sessions("mysession", store))

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://127.0.0.1:8080"}
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	config.AllowCredentials = true
	router.Use(cors.New(config))

	// サインインAPI
	router.POST("/signin", func(c *gin.Context) {
		var user struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// パスワードをハッシュ化
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// ユーザーをデータベースに保存
		var exists bool
		err = sqlDb.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", user.Email).Scan(&exists)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// メールアドレスの存在チェック
		if exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "このメールアドレスは既に登録されています"})
			return
		}

		// エラーなしの場合はINSERT処理を実行
		_, err = sqlDb.Exec("INSERT INTO users (email, password) VALUES ($1, $2)", user.Email, string(hashedPassword))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "サインインに成功しました"})
	})

	// ログインAPI
	router.POST("/login", func(c *gin.Context) {
		var credentials struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		// JSON形式にバインド
		if err := c.ShouldBindJSON(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// データベースからユーザーを取得
		var hashedPassword string
		err := sqlDb.QueryRow("SELECT password FROM users WHERE email = $1", credentials.Email).Scan(&hashedPassword)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "メールアドレスまたはパスワードが間違っています。"})
			return
		}

		// パスワードを検証
		if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "メールアドレスまたはパスワードが間違っています。"})
			return
		}

		// セッションにユーザー名を保存する処理)
		row := sqlDb.QueryRow("SELECT * FROM users WHERE email = $1", credentials.Email)
		var record struct {
			ID       int    `json:"id"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		err = row.Scan(&record.ID, &record.Email, &record.Password)
		// エラー判定
		if err != nil {
			if err == sql.ErrNoRows {
				// レコードが見つからない場合
				c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
				return
			}

			// その他のエラー
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// セッションを開始
		session := sessions.Default(c)
		session.Set(sessionKey, record.ID)
		if err := session.Save(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// ログイン成功時のレスポンス
		c.JSON(http.StatusOK, gin.H{"message": "ログインに成功しました"})
	})

	// ログアウトAPI
	router.POST("/logout", func(c *gin.Context) {
		// セッションを破棄
		session := sessions.Default(c)
		session.Delete(sessionKey)
		session.Options(sessions.Options{Path: "/", MaxAge: -1})
		session.Clear()
		session.Save()
		// Cookieの削除
		c.SetCookie("mysession", "", -1, "/", "", false, true)

		c.JSON(http.StatusOK, gin.H{"message": "ログアウトに成功しました"})
	})

	// 学習記録を取得するAPI
	router.GET("/records", indexAuthMiddleware, func(c *gin.Context) {

		// セッションからユーザーIDを取得
		session := sessions.Default(c)
		userID := session.Get(sessionKey)

		var userIDstr string
		if userID == nil {
			userIDstr = "0"
		} else {
			userIDstr = strconv.Itoa(userID.(int))
		}

		// ユーザーIDに基づいて学習記録を取得
		rows, err := sqlDb.Query("SELECT * FROM study_records WHERE user_id = $1", userIDstr) // WHERE句を追加
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var records []struct {
			ID             int    `json:"id"`
			StudyDate      string `json:"study_date"`
			StudyStartTime string `json:"study_start_time"`
			StudyEndTime   string `json:"study_end_time"`
			Category       string `json:"category"`
			UserID         string `json:"userid"`
		}
		// DBより取得したレコードを構造体に展開する
		for rows.Next() {
			var record struct {
				ID             int    `json:"id"`
				StudyDate      string `json:"study_date"`
				StudyStartTime string `json:"study_start_time"`
				StudyEndTime   string `json:"study_end_time"`
				Category       string `json:"category"`
				UserID         string `json:"userid"`
			}
			err := rows.Scan(&record.ID, &record.StudyDate, &record.StudyStartTime, &record.StudyEndTime, &record.Category, &record.UserID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			records = append(records, record)
		}

		c.JSON(http.StatusOK, records)
	})

	// 学習記録を保存するAPI
	router.POST("/records", indexAuthMiddleware, func(c *gin.Context) {

		// WEB画面より受け取ったJSON
		var record struct {
			StudyDate      string `json:"study_date"`
			StudyStartTime string `json:"study_start_time"`
			StudyEndTime   string `json:"study_end_time"`
			Category       string `json:"category"`
		}

		if err := c.ShouldBindJSON(&record); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// セッションからユーザーIDを取得
		session := sessions.Default(c)
		userID := session.Get(sessionKey)
		var userIDstr string

		if userID == nil {
			userIDstr = "0"
		} else {
			userIDstr = strconv.Itoa(userID.(int))
		}
		// 学習記録をデータベースに保存
		err = db.SaveRecord(sqlDb, record.StudyDate, record.StudyStartTime, record.StudyEndTime, record.Category, userIDstr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "学習記録を保存しました"})
	})

	// 学習記録の詳細情報を取得するAPI
	router.GET("/records/:id", indexAuthMiddleware, func(c *gin.Context) {

		recordID := c.Param("id")

		var record struct {
			ID             int    `json:"id"`
			StudyDate      string `json:"study_date"`
			StudyStartTime string `json:"study_start_time"`
			StudyEndTime   string `json:"study_end_time"`
			Category       string `json:"category"`
			UserID         string `json:"userid"`
		}
		// DBのレコード情報を展開
		err := sqlDb.QueryRow("SELECT * FROM study_records WHERE id = $1", recordID).Scan(&record.ID, &record.StudyDate, &record.StudyStartTime, &record.StudyEndTime, &record.Category, &record.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, record)
	})

	// 学習記録を更新するAPI
	router.PUT("/records/:id", indexAuthMiddleware, func(c *gin.Context) {
		recordID := c.Param("id")

		var record struct {
			StudyDate      string `json:"study_date"`
			StudyStartTime string `json:"study_start_time"`
			StudyEndTime   string `json:"study_end_time"`
			Category       string `json:"category"`
		}
		// JSON形式にバインド
		if err := c.ShouldBindJSON(&record); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// UPDATE処理を実行
		_, err := sqlDb.Exec(
			`UPDATE study_records SET study_date = $1, study_start_time = $2, study_end_time = $3, category = $4 WHERE id = $5`,
			record.StudyDate, record.StudyStartTime, record.StudyEndTime, record.Category, recordID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "学習記録を更新しました"})
	})

	// 学習記録を削除するAPI
	router.DELETE("/records/:id", indexAuthMiddleware, func(c *gin.Context) {

		recordID := c.Param("id")
		// 削除処理を実行
		_, err := sqlDb.Exec("DELETE FROM study_records WHERE id = $1", recordID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "学習記録を削除しました"})
	})

	// 学習成果を取得するAPI
	router.GET("/results", indexAuthMiddleware, func(c *gin.Context) {
		period := c.Query("period") // クエリパラメータ period を取得

		// セッションからユーザーIDを取得
		session := sessions.Default(c)
		userID := session.Get(sessionKey)
		var userIDstr string
		if userID == nil {
			userIDstr = "0"
		} else {
			userIDstr = strconv.Itoa(userID.(int))
		}

		// 期間に応じた SQL クエリを生成
		var query string
		switch period {
		// １日
		case "day":
			query = fmt.Sprintf(
				`SELECT category, SUM(study_end_time - study_start_time) AS total_time FROM study_records WHERE study_date = CURRENT_DATE AND user_id = %s GROUP BY category`, userIDstr)
			// １週間
		case "week":
			query = fmt.Sprintf(
				`SELECT category, SUM(study_end_time - study_start_time) AS total_time FROM study_records WHERE study_date >= CURRENT_DATE - INTERVAL '7 days' AND user_id = %s GROUP BY category`, userIDstr)
			// １ヶ月
		case "month":
			query = fmt.Sprintf(
				`SELECT category, SUM(study_end_time - study_start_time) AS total_time FROM study_records WHERE study_date >= CURRENT_DATE - INTERVAL '1 month' AND user_id = %s GROUP BY category`, userIDstr)
		// １年間
		case "year":
			query = fmt.Sprintf(
				`SELECT category, SUM(study_end_time - study_start_time) AS total_time FROM study_records WHERE study_date >= CURRENT_DATE - INTERVAL '1 year' AND user_id = %s GROUP BY category`, userIDstr)
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid period"})
			return
		}

		// SQL クエリを実行
		rows, err := sqlDb.Query(query)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var results []struct {
			Category  string `json:"category"`
			TotalTime string `json:"totalTime"`
		}
		// DBより取得したデータを構造体に展開する
		for rows.Next() {
			var result struct {
				Category  string `json:"category"`
				TotalTime string `json:"totalTime"`
			}
			err := rows.Scan(&result.Category, &result.TotalTime)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			results = append(results, result)
		}

		c.JSON(http.StatusOK, results)
	})

	router.Run(":8080")

}

// index.htmlへのアクセス時に認証状態を確認するミドルウェア
func indexAuthMiddleware(c *gin.Context) {

	// セッションからユーザーIDを取得
	session := sessions.Default(c)
	userID := session.Get(sessionKey)

	if userID == nil {
		fmt.Println("indexAuthMiddleware 認証エラー")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "認証エラー"})
		return
	}
	c.Next()
}

// ランダム値作成
func generateRandomKey(length int) string {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal("Error generating random key:", err)
	}
	return base64.StdEncoding.EncodeToString(key)
}
