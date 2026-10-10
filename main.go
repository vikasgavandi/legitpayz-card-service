// Card Service: products, issuance, PIN set/verify, balance (Redis cached),
// upgrade / downgrade, block/unblock/close.
// Run: PORT=8002 go run ./services/card-service
package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/vikasgavandi/legitpayz-card-service/pkg/cache"
	"github.com/vikasgavandi/legitpayz-card-service/pkg/db"
	"github.com/vikasgavandi/legitpayz-card-service/pkg/events"
	"github.com/vikasgavandi/legitpayz-card-service/pkg/obs"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var rdb = cache.Client()

func genCardNumber() (string, string) {
	// 16-digit starting with 4, last4 returned separately
	n := "4"
	for i := 0; i < 15; i++ {
		n += fmt.Sprint(rand.Intn(10))
	}
	return n, n[12:]
}

func main() {
	rand.Seed(time.Now().UnixNano())
	database, err := db.Connect()
	if err != nil {
		panic(err)
	}
	defer database.Close()

	r := obs.Engine("card")

	r.GET("/products", func(c *gin.Context) {
		rows, err := database.Query(`SELECT code,name,credit_limit_min,credit_limit_max,annual_fee,interest_rate_apr,facilities,rank FROM card_products ORDER BY rank`)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var code, name, fac string
			var mn, mx, fee int64
			var apr float64
			var rank int
			_ = rows.Scan(&code, &name, &mn, &mx, &fee, &apr, &fac, &rank)
			out = append(out, map[string]any{"code": code, "name": name, "min": mn, "max": mx, "annual_fee": fee, "apr": apr, "facilities": fac, "rank": rank})
		}
		c.JSON(200, out)
	})

	// Credit card application / issuance
	r.POST("/cards/apply", func(c *gin.Context) {
		var req struct {
			CustomerID  string `json:"customer_id" binding:"required"`
			ProductCode string `json:"product_code" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		var kyc string
		var score int
		if err := database.QueryRow(`SELECT kyc_status, credit_score FROM customers WHERE id=$1`, req.CustomerID).Scan(&kyc, &score); err != nil {
			c.JSON(404, gin.H{"error": "customer not found"})
			return
		}
		if kyc != "VERIFIED" {
			c.JSON(403, gin.H{"error": "KYC not verified"})
			return
		}
		var mn, mx int64
		var rank int
		if err := database.QueryRow(`SELECT credit_limit_min, credit_limit_max, rank FROM card_products WHERE code=$1`, req.ProductCode).Scan(&mn, &mx, &rank); err != nil {
			c.JSON(400, gin.H{"error": "unknown product"})
			return
		}
		// Limit scales with credit score
		limit := mn + int64(float64(mx-mn)*float64(score-550)/350.0)
		if limit < mn {
			limit = mn
		}
		if limit > mx {
			limit = mx
		}
		num, last4 := genCardNumber()
		cvvHash, _ := bcrypt.GenerateFromPassword([]byte(fmt.Sprint(100+rand.Intn(900))), bcrypt.MinCost)
		id := uuid.New().String()
		expiry := time.Now().AddDate(5, 0, 0).Format("2006-01-02")
		_, err = database.Exec(`INSERT INTO credit_cards(id,customer_id,product_code,card_number,last4,cvv_hash,status,credit_limit,expiry) VALUES($1,$2,$3,$4,$5,$6,'ACTIVE',$7,$8)`,
			id, req.CustomerID, req.ProductCode, num, last4, string(cvvHash), limit, expiry)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		_, _ = database.Exec(`INSERT INTO card_events(card_id,event,meta) VALUES($1,'ISSUED',$2)`, id, `{"product":"`+req.ProductCode+`"}`)
		_ = events.Default.Publish("card.events", id, `{"event":"ISSUED","card_id":"`+id+`"}`)
		cache.SetBalance(rdb, id, 0)
		c.JSON(201, gin.H{"card_id": id, "last4": last4, "credit_limit": limit, "status": "ACTIVE", "note": "Set PIN via POST /cards/:id/pin"})
	})

	// Set / change PIN (bcrypt hash; prod: HSM / Secrets Manager)
	r.POST("/cards/:id/pin", func(c *gin.Context) {
		var req struct {
			Pin    string `json:"pin" binding:"required,len=4"`
			OldPin string `json:"old_pin"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		var cur sql.NullString
		if err := database.QueryRow(`SELECT pin_hash FROM credit_cards WHERE id=$1`, c.Param("id")).Scan(&cur); err != nil {
			c.JSON(404, gin.H{"error": "card not found"})
			return
		}
		if cur.Valid {
			if req.OldPin == "" || bcrypt.CompareHashAndPassword([]byte(cur.String), []byte(req.OldPin)) != nil {
				c.JSON(403, gin.H{"error": "old PIN required / invalid"})
				return
			}
		}
		h, _ := bcrypt.GenerateFromPassword([]byte(req.Pin), bcrypt.DefaultCost)
		_, _ = database.Exec(`UPDATE credit_cards SET pin_hash=$1, pin_attempts=0, updated_at=now() WHERE id=$2`, string(h), c.Param("id"))
		_, _ = database.Exec(`INSERT INTO card_events(card_id,event) VALUES($1,'PIN_SET')`, c.Param("id"))
		_ = events.Default.Publish("card.events", c.Param("id"), `{"event":"PIN_SET"}`)
		c.JSON(200, gin.H{"ok": true})
	})

	// Verify PIN (3 wrong attempts -> BLOCKED)
	r.POST("/cards/:id/pin/verify", func(c *gin.Context) {
		var req struct {
			Pin string `json:"pin" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		var h sql.NullString
		var attempts int
		var status string
		if err := database.QueryRow(`SELECT pin_hash,pin_attempts,status FROM credit_cards WHERE id=$1`, c.Param("id")).Scan(&h, &attempts, &status); err != nil {
			c.JSON(404, gin.H{"error": "card not found"})
			return
		}
		if status != "ACTIVE" {
			c.JSON(403, gin.H{"error": "card " + status})
			return
		}
		if !h.Valid {
			c.JSON(403, gin.H{"error": "PIN not set"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(h.String), []byte(req.Pin)) != nil {
			attempts++
			if attempts >= 3 {
				_, _ = database.Exec(`UPDATE credit_cards SET pin_attempts=$1,status='BLOCKED' WHERE id=$2`, attempts, c.Param("id"))
				c.JSON(403, gin.H{"error": "card blocked after 3 attempts"})
				return
			}
			_, _ = database.Exec(`UPDATE credit_cards SET pin_attempts=$1 WHERE id=$2`, attempts, c.Param("id"))
			c.JSON(401, gin.H{"error": "wrong PIN", "attempts_left": 3 - attempts})
			return
		}
		_, _ = database.Exec(`UPDATE credit_cards SET pin_attempts=0 WHERE id=$1`, c.Param("id"))
		c.JSON(200, gin.H{"ok": true})
	})

	// Balance (Redis cached used_limit)
	r.GET("/cards/:id/balance", func(c *gin.Context) {
		id := c.Param("id")
		var limit, used int64
		var product, status string
		if err := database.QueryRow(`SELECT credit_limit,used_limit,product_code,status FROM credit_cards WHERE id=$1`, id).Scan(&limit, &used, &product, &status); err != nil {
			c.JSON(404, gin.H{"error": "card not found"})
			return
		}
		cache.SetBalance(rdb, id, used)
		c.JSON(200, gin.H{"card_id": id, "product": product, "status": status,
			"credit_limit": limit, "used_limit": used, "available": limit - used})
	})

	// Upgrade / Downgrade
	r.POST("/cards/:id/change-product", func(c *gin.Context) {
		var req struct {
			NewProduct string `json:"new_product" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		var cur string
		var limit int64
		if err := database.QueryRow(`SELECT product_code,credit_limit FROM credit_cards WHERE id=$1`, c.Param("id")).Scan(&cur, &limit); err != nil {
			c.JSON(404, gin.H{"error": "card not found"})
			return
		}
		var curRank, newRank int
		var newMin, newMax, newFee int64
		_ = database.QueryRow(`SELECT rank FROM card_products WHERE code=$1`, cur).Scan(&curRank)
		if err := database.QueryRow(`SELECT rank,credit_limit_min,credit_limit_max,annual_fee FROM card_products WHERE code=$1`, req.NewProduct).Scan(&newRank, &newMin, &newMax, &newFee); err != nil {
			c.JSON(400, gin.H{"error": "unknown product"})
			return
		}
		action := "SAME"
		if newRank > curRank {
			action = "UPGRADED"
		} else if newRank < curRank {
			action = "DOWNGRADED"
		}
		newLimit := limit
		if newLimit < newMin {
			newLimit = newMin
		}
		if newLimit > newMax {
			newLimit = newMax
		}
		_, _ = database.Exec(`UPDATE credit_cards SET product_code=$1,credit_limit=$2,updated_at=now() WHERE id=$3`, req.NewProduct, newLimit, c.Param("id"))
		_, _ = database.Exec(`INSERT INTO card_events(card_id,event,meta) VALUES($1,$2,$3)`, c.Param("id"), action, `{"from":"`+cur+`","to":"`+req.NewProduct+`"}`)
		_ = events.Default.Publish("card.events", c.Param("id"), `{"event":"`+action+`"}`)
		c.JSON(200, gin.H{"action": action, "product": req.NewProduct, "credit_limit": newLimit, "annual_fee": newFee})
	})

	r.POST("/cards/:id/block", func(c *gin.Context) {
		_, _ = database.Exec(`UPDATE credit_cards SET status='BLOCKED' WHERE id=$1`, c.Param("id"))
		c.JSON(200, gin.H{"status": "BLOCKED"})
	})
	r.POST("/cards/:id/unblock", func(c *gin.Context) {
		_, _ = database.Exec(`UPDATE credit_cards SET status='ACTIVE', pin_attempts=0 WHERE id=$1`, c.Param("id"))
		c.JSON(200, gin.H{"status": "ACTIVE"})
	})
	r.GET("/cards/customer/:cid", func(c *gin.Context) {
		rows, _ := database.Query(`SELECT id,product_code,last4,status,credit_limit,used_limit,expiry FROM credit_cards WHERE customer_id=$1`, c.Param("cid"))
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var id, p, last4, st, exp string
			var lim, used int64
			_ = rows.Scan(&id, &p, &last4, &st, &lim, &used, &exp)
			out = append(out, map[string]any{"card_id": id, "product": p, "last4": last4, "status": st, "limit": lim, "used": used, "available": lim - used, "expiry": exp})
		}
		c.JSON(200, out)
	})

	r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true, "svc": "card"}) })

	port := os.Getenv("PORT")
	if port == "" {
		port = "8002"
	}
	_ = r.Run(":" + port)
}
