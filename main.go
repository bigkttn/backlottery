package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	db *sql.DB
}

func main() {
	// 🔑 เชื่อม MySQL (ใช้ & ตรง ๆ ไม่ต้อง escape)
	user := "mb68_66011212250"
	pass := "&WH74jVmJE6b"
	host := "202.28.34.203"
	port := "3306"
	dbname := "mb68_66011212250"

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&loc=Local",
		user, pass, host, port, dbname)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("open error:", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatal("ping error:", err)
	}
	fmt.Println("✅ Connected to MySQL!")
	ip := getLocalIPv4()
	fmt.Printf("👉 http://%s:8080/api/health\n", ip)

	s := &Server{db: db}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.health)
	mux.HandleFunc("/api/register", s.register)        // สมัครสมาชิก
	mux.HandleFunc("/api/login", s.login)              // เข้าสู่ระบบ
	mux.HandleFunc("/api/user", s.getUser)             // ดึงข้อมูล user
	mux.HandleFunc("/api/wallet/topup", s.topUpWallet) // เติมเงิน wallet
	mux.HandleFunc("/api/lottery/generate/", s.generateLotteryPath)
	mux.HandleFunc("/api/lottery", s.getLottery) // GET lottery
	mux.HandleFunc("/api/reward/insert", s.insertReward)
	mux.HandleFunc("/api/reward/get", s.getReward)
	mux.HandleFunc("/api/buy", s.buyLottery)

	// ✅ เพิ่ม CORS ให้อ่านได้จากมือถือ/Flutter
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		mux.ServeHTTP(w, r)
	})

	log.Println("🌍 API running at :8080 ...")
	// log.Fatal(http.ListenAndServe(":8080", handler))
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", handler))

}
func getLocalIPv4() string {
	conn, err := net.Dial("udp4", "8.8.8.8:80") // ใช้ udp4 บังคับ IPv4
	if err != nil {
		return "127.0.0.1" // default IPv4
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "ts": time.Now()})
}

// ====================== REGISTER =========================
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var raw map[string]any
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeJSON(w, 400, errMsg("bad json"))
		return
	}

	getStr := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k]; ok && v != nil {
				if s, ok := v.(string); ok {
					return strings.TrimSpace(s)
				}
			}
		}
		return ""
	}

	email := getStr("email")
	password := getStr("password")
	fullName := getStr("full_name", "fullname", "name")
	phone := getStr("phone", "phoneNo", "tel")

	// money optional
	var money int
	if v, ok := raw["money"]; ok {
		switch t := v.(type) {
		case float64:
			money = int(t)
		case string:
			if x, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
				money = x
			}
		}
	}

	if email == "" || password == "" || fullName == "" || phone == "" {
		writeJSON(w, 400, errMsg("email/password/full_name/phone required"))
		return
	}

	// ✅ hash password ก่อนเก็บ
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, 500, errMsg("failed to hash password"))
		return
	}

	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM user WHERE phone=?`, phone).Scan(&exists); err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	if exists > 0 {
		writeJSON(w, 409, errMsg("phone already exists"))
		return
	}

	// ✅ ใช้ hashedPassword แทน password
	res, err := s.db.Exec(`
		INSERT INTO user (email, password, full_name, phone, role, money)
		VALUES (?, ?, ?, ?, 'MEMBER', ?)`,
		email, string(hashedPassword), fullName, phone, money)
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	id, _ := res.LastInsertId()
	writeJSON(w, 201, map[string]any{"uid": id})
}

// ====================== LOGIN =========================
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var req struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, errMsg("bad json"))
		return
	}

	var u struct {
		Uid      int    `json:"uid"`
		Email    string `json:"email"`
		FullName string `json:"full_name"`
		Phone    string `json:"phone"`
		Role     string `json:"role"`
		Money    int    `json:"money"`
		Password string // ใช้เก็บ hash password จาก DB
	}

	// ✅ ดึง hash password จาก DB ด้วย phone
	err := s.db.QueryRow(
		`SELECT uid, email, full_name, phone, role, money, password 
		 FROM user WHERE phone=?`, req.Phone,
	).Scan(&u.Uid, &u.Email, &u.FullName, &u.Phone, &u.Role, &u.Money, &u.Password)

	if err == sql.ErrNoRows {
		writeJSON(w, 401, errMsg("invalid phone or password"))
		return
	}
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}

	// ✅ ตรวจสอบ password
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(req.Password)) != nil {
		writeJSON(w, 401, errMsg("invalid phone or password"))
		return
	}

	// ✅ ลบ password ออกจาก response
	u.Password = ""

	writeJSON(w, 200, map[string]any{"user": u})
}

// ====================== UTIL =========================
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ====================== GET USER =========================
func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	// ดึง uid จาก query ?uid=123
	uidStr := r.URL.Query().Get("uid")
	if uidStr == "" {
		writeJSON(w, 400, errMsg("uid required"))
		return
	}
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		writeJSON(w, 400, errMsg("invalid uid"))
		return
	}

	var u struct {
		Uid      int    `json:"uid"`
		Email    string `json:"email"`
		FullName string `json:"full_name"`
		Phone    string `json:"phone"`
		Role     string `json:"role"`
		Money    int    `json:"wallet"`
	}

	err = s.db.QueryRow(
		`SELECT uid, email, full_name, phone, role, money 
		 FROM user WHERE uid=?`, uid,
	).Scan(&u.Uid, &u.Email, &u.FullName, &u.Phone, &u.Role, &u.Money)

	if err == sql.ErrNoRows {
		writeJSON(w, 404, errMsg("user not found"))
		return
	}
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}

	writeJSON(w, 200, u)
}

// ====================== TOP-UP WALLET =========================
func (s *Server) topUpWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var req struct {
		Uid    int `json:"uid"`
		Amount int `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, errMsg("bad json"))
		return
	}

	if req.Amount <= 0 {
		writeJSON(w, 400, errMsg("amount must be > 0"))
		return
	}

	_, err := s.db.Exec(`UPDATE user SET money = money + ? WHERE uid = ?`, req.Amount, req.Uid)
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}

	writeJSON(w, 200, map[string]any{"message": "wallet updated"})
}

func errMsg(m string) map[string]any { return map[string]any{"error": m} }

// ====================== GENERATE LOTTERY =========================
func (s *Server) generateLotteryPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		writeJSON(w, 400, errMsg("user_id missing in path"))
		return
	}

	userID, err := strconv.Atoi(parts[4])
	if err != nil || userID <= 0 {
		writeJSON(w, 400, errMsg("invalid user_id"))
		return
	}

	today := time.Now().Format("2006-01-02")
	price := 80
	count := 100

	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	_, err = tx.Exec(`DELETE FROM reward`)
	if err != nil {
		tx.Rollback()
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	// ลบล็อตเตอรี่ทั้งหมดก่อน (ทุกวัน ทุก user)
	_, err = tx.Exec(`DELETE FROM lottery`)
	if err != nil {
		tx.Rollback()
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}

	existing := map[int]bool{}

	randomNumber := func() int {
		for {
			num := 100000 + rand.Intn(900000)
			if !existing[num] {
				existing[num] = true
				return num
			}
		}
	}

	stmt, err := tx.Prepare(`INSERT INTO lottery (number, price, status, date, user_id) VALUES (?, ?, 'ยังไม่ขาย', ?, ?)`)
	if err != nil {
		tx.Rollback()
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	defer stmt.Close()

	inserted := []int{}
	for i := 0; i < count; i++ {
		num := randomNumber()
		_, err := stmt.Exec(num, price, today, userID)
		if err != nil {
			tx.Rollback()
			writeJSON(w, 500, errMsg(err.Error()))
			return
		}
		inserted = append(inserted, num)
	}

	if err := tx.Commit(); err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}

	writeJSON(w, 201, map[string]any{
		"user_id":  userID,
		"inserted": inserted,
		"count":    len(inserted),
		"price":    price,
		"date":     today,
	})
}

// ====================== GET LOTTERY =========================
func (s *Server) getLottery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	// เพิ่ม lid ใน SELECT
	rows, err := s.db.Query("SELECT lid, number, price, status, date, user_id FROM lottery")
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	defer rows.Close()

	type Lottery struct {
		LID    int    `json:"lid"` // เพิ่ม field lid
		Number int    `json:"number"`
		Price  int    `json:"price"`
		Status string `json:"status"`
		Date   string `json:"date"`
		UserID int    `json:"user_id"`
	}

	lots := []Lottery{}
	for rows.Next() {
		var l Lottery
		if err := rows.Scan(&l.LID, &l.Number, &l.Price, &l.Status, &l.Date, &l.UserID); err != nil {
			writeJSON(w, 500, errMsg(err.Error()))
			return
		}
		lots = append(lots, l)
	}

	writeJSON(w, 200, lots)
}

// ====================== insert reward =========================

func (s *Server) insertReward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	today := time.Now().Format("2006-01-02")
	tx, err := s.db.Begin()
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	// ลบรางวัลเก่าทั้งหมด
	_, err = tx.Exec(`DELETE FROM reward`)

	// ดึงเลขล็อตเตอรี่วันนี้
	rows, err := s.db.Query("SELECT lid, number FROM lottery WHERE date=?", today)
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	defer rows.Close()

	type Lotto struct {
		LID    int
		Number string
	}

	var all []Lotto
	for rows.Next() {
		var l Lotto
		rows.Scan(&l.LID, &l.Number)
		all = append(all, l)
	}
	if len(all) == 0 {
		writeJSON(w, 400, errMsg("no lottery for today"))
		return
	}

	rand.Seed(time.Now().UnixNano())

	// tx, err := s.db.Begin()
	// if err != nil {
	// 	writeJSON(w, 500, errMsg(err.Error()))
	// 	return

	// }

	stmt, err := tx.Prepare(`INSERT INTO reward (type, money, lottery_id) VALUES (?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	defer stmt.Close()

	results := []map[string]any{}

	// รางวัลที่ 1,2,3 : เลือก 1 ตัว
	topPrizes := []struct {
		Type  string
		Money int
	}{
		{"รางวัลที่ 1", 6000000},
		{"รางวัลที่ 2", 200000},
		{"รางวัลที่ 3", 80000},
	}
	for _, p := range topPrizes {
		l := all[rand.Intn(len(all))]
		_, err := stmt.Exec(p.Type, p.Money, l.LID)
		if err != nil {
			tx.Rollback()
			writeJSON(w, 500, errMsg(err.Error()))
			return
		}
		results = append(results, map[string]any{
			"type":       p.Type,
			"money":      p.Money,
			"lottery_id": l.LID,
		})
	}

	// เลขท้าย 2 ตัว: สุ่มเลขท้ายจากล็อตเตอรี่จริง
	twoDigitCandidates := []Lotto{}
	for _, l := range all {
		if len(l.Number) >= 2 {
			twoDigitCandidates = append(twoDigitCandidates, l)
		}
	}

	if len(twoDigitCandidates) > 0 {
		chosen := twoDigitCandidates[rand.Intn(len(twoDigitCandidates))]
		suffix2 := chosen.Number[len(chosen.Number)-2:]

		for _, l := range all {
			if len(l.Number) >= 2 && l.Number[len(l.Number)-2:] == suffix2 {
				_, err := stmt.Exec("เลขท้าย 2 ตัว", 2000, l.LID)
				if err != nil {
					tx.Rollback()
					writeJSON(w, 500, errMsg(err.Error()))
					return
				}
				results = append(results, map[string]any{
					"type":       "เลขท้าย 2 ตัว",
					"money":      2000,
					"lottery_id": l.LID,
				})
			}
		}
	}

	// เลขท้าย 3 ตัว: สุ่มเลขท้ายจากล็อตเตอรี่จริง
	threeDigitCandidates := []Lotto{}
	for _, l := range all {
		if len(l.Number) >= 3 {
			threeDigitCandidates = append(threeDigitCandidates, l)
		}
	}

	if len(threeDigitCandidates) > 0 {
		chosen := threeDigitCandidates[rand.Intn(len(threeDigitCandidates))]
		suffix3 := chosen.Number[len(chosen.Number)-3:]

		for _, l := range all {
			if len(l.Number) >= 3 && l.Number[len(l.Number)-3:] == suffix3 {
				_, err := stmt.Exec("เลขท้าย 3 ตัว", 4000, l.LID)
				if err != nil {
					tx.Rollback()
					writeJSON(w, 500, errMsg(err.Error()))
					return
				}
				results = append(results, map[string]any{
					"type":       "เลขท้าย 3 ตัว",
					"money":      4000,
					"lottery_id": l.LID,
				})
			}
		}
	}

	if err := tx.Commit(); err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}

	writeJSON(w, 201, results)
}

// ====================== get reward =========================

func (s *Server) getReward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	// Join reward กับ lottery เพื่อเอาเลขล็อตเตอรี่
	rows, err := s.db.Query(`
		SELECT r.rid, r.money, r.type, r.lottery_id, l.number
		FROM reward r
		JOIN lottery l ON r.lottery_id = l.lid
	`)
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	defer rows.Close()

	type Reward struct {
		Rid       int    `json:"rid"`
		Money     int    `json:"money"`
		Type      string `json:"type"`
		LotteryID int    `json:"lottery_id"`
		Number    string `json:"number"`
	}

	lots := []Reward{}
	for rows.Next() {
		var r Reward
		if err := rows.Scan(&r.Rid, &r.Money, &r.Type, &r.LotteryID, &r.Number); err != nil {
			writeJSON(w, 500, errMsg(err.Error()))
			return
		}
		lots = append(lots, r)
	}

	writeJSON(w, 200, lots)
}

// ====================== Buy Lottery =========================
func (s *Server) buyLottery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	// อ่าน body
	var req struct {
		UserID    int `json:"userId"`
		LotteryID int `json:"lotteryId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, errMsg("bad json"))
		return
	}

	// เริ่ม transaction
	tx, err := s.db.Begin()
	if err != nil {
		log.Println("Error starting transaction:", err)
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	defer tx.Rollback()

	// ดึงข้อมูลสลาก
	var price int
	var status string
	var date string
	err = tx.QueryRow(`
		SELECT price, status, date 
		FROM lottery 
		WHERE lid=? FOR UPDATE`,
		req.LotteryID).Scan(&price, &status, &date)
	if err == sql.ErrNoRows {
		log.Println("Lottery not found with lid:", req.LotteryID)
		writeJSON(w, 404, errMsg("ไม่พบสลากนี้"))
		return
	}
	if err != nil {
		log.Println("Error querying lottery:", err)
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	log.Printf("Successfully retrieved lottery %d. Status: %s, Price: %d", req.LotteryID, status, price)

	// ตรวจสอบว่าสลากยังไม่ขาย
	if status != "ยังไม่ขาย" {
		writeJSON(w, 400, errMsg("สลากนี้ขายแล้ว"))
		return
	}

	// ดึงยอดเงินผู้ใช้
	var money int
	err = tx.QueryRow("SELECT money FROM user WHERE uid=? FOR UPDATE", req.UserID).Scan(&money)
	if err != nil {
		log.Println("Error querying user money:", err)
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	log.Printf("Successfully retrieved user %d. Current money: %d", req.UserID, money)

	if money < price {
		writeJSON(w, 400, errMsg("เงินไม่พอซื้อสลาก"))
		return
	}

	// insert ลง buylottery (ใช้ DATETIME สำหรับ date)
	_, err = tx.Exec(`
    INSERT INTO buylottery (status_buy, date, lottery_id, user_id)
    VALUES (?, ?, ?, ?)`,
		"ยังไม่ตรวจ", time.Now().Format("2006-01-02 15:04:05"), req.LotteryID, req.UserID)
	if err != nil {
		// This log is crucial for debugging your problem
		log.Println("Error inserting into buylottery:", err)
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}
	log.Println("Successfully inserted into buylottery table.")

	// update lottery status
	_, err = tx.Exec("UPDATE lottery SET status='ขายแล้ว' WHERE lid=?", req.LotteryID)
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}

	// หักเงินผู้ใช้
	_, err = tx.Exec("UPDATE user SET money = money - ? WHERE uid=?", price, req.UserID)
	if err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}

	// commit transaction
	if err := tx.Commit(); err != nil {
		writeJSON(w, 500, errMsg(err.Error()))
		return
	}

	// ส่ง response
	writeJSON(w, 200, map[string]any{
		"message":   "ซื้อสลากสำเร็จ",
		"userId":    req.UserID,
		"lotteryId": req.LotteryID,
		"price":     price,
		"statusBuy": "ยังตรวจ",
		"date":      date,
	})
}
