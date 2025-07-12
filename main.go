// main.go - SecureProxy Simplified (~350 lines)
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/time/rate"
)

// ============================================================================
// TYPES
// ============================================================================

type User struct {
	ID         string    `json:"id"`
	Email      string    `json:"email"`
	AllowedIPs []string  `json:"allowed_ips"`
	CreatedAt  time.Time `json:"created_at"`
}

type ProxyServer struct {
	db        *sql.DB
	masterKey []byte
	limiters  map[string]*rate.Limiter
	mu        sync.Mutex
}

// ============================================================================
// CRYPTO & DATABASE
// ============================================================================

func encrypt(data, key []byte) (string, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encryptedData string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid data")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func initDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	
	schema := `
	CREATE TABLE IF NOT EXISTS services (
		name TEXT PRIMARY KEY,
		base_url TEXT NOT NULL,
		auth_header TEXT NOT NULL,
		auth_scheme TEXT,
		encrypted_api_key TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT NOT NULL UNIQUE,
		token_hash TEXT NOT NULL UNIQUE,
		allowed_ips TEXT,
		created_at DATETIME NOT NULL
	);`
	
	_, err = db.Exec(schema)
	return db, err
}

func loadMasterKey(keyFile string) ([]byte, error) {
	if data, err := os.ReadFile(keyFile); err == nil {
		return data, nil
	}
	
	key := make([]byte, 32)
	rand.Read(key)
	os.WriteFile(keyFile, key, 0600)
	return key, nil
}

// ============================================================================
// PROXY SERVER
// ============================================================================

func NewProxyServer() (*ProxyServer, error) {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".secureproxy")
	os.MkdirAll(configDir, 0700)
	
	masterKey, err := loadMasterKey(filepath.Join(configDir, "master.key"))
	if err != nil {
		return nil, err
	}
	
	db, err := initDB(filepath.Join(configDir, "proxy.db"))
	if err != nil {
		return nil, err
	}
	
	// Add default services
	defaultServices := map[string][]string{
		"openai":    {"https://api.openai.com", "Authorization", "Bearer"},
		"anthropic": {"https://api.anthropic.com", "x-api-key", ""},
		"stripe":    {"https://api.stripe.com", "Authorization", "Bearer"},
		"github":    {"https://api.github.com", "Authorization", "token"},
	}
	
	for name, config := range defaultServices {
		db.Exec("INSERT OR IGNORE INTO services (name, base_url, auth_header, auth_scheme, encrypted_api_key) VALUES (?, ?, ?, ?, '')", 
			name, config[0], config[1], config[2])
	}
	
	return &ProxyServer{
		db:        db,
		masterKey: masterKey,
		limiters:  make(map[string]*rate.Limiter),
	}, nil
}

func (p *ProxyServer) Start() error {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})
	
	// Proxy routes with middleware
	proxy := r.Group("/proxy")
	proxy.Use(p.authMiddleware)
	proxy.Use(p.rateLimitMiddleware)
	proxy.Any("/:service/*path", p.handleProxy)
	
	fmt.Println("🚀 SecureProxy running on port 8080")
	return r.Run(":8080")
}

func (p *ProxyServer) authMiddleware(c *gin.Context) {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if token == "" {
		c.JSON(401, gin.H{"error": "Missing token"})
		c.Abort()
		return
	}
	
	// Hash token for secure comparison
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashStr := base64.StdEncoding.EncodeToString(tokenHash[:])
	
	var user User
	var allowedIPsJSON string
	err := p.db.QueryRow("SELECT id, email, allowed_ips, created_at FROM users WHERE token_hash = ?", 
		tokenHashStr).Scan(&user.ID, &user.Email, &allowedIPsJSON, &user.CreatedAt)
	
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}
	
	// Check IPs if configured
	if allowedIPsJSON != "" {
		json.Unmarshal([]byte(allowedIPsJSON), &user.AllowedIPs)
		if len(user.AllowedIPs) > 0 {
			clientIP := c.ClientIP()
			allowed := false
			for _, ip := range user.AllowedIPs {
				if ip == clientIP || ip == "0.0.0.0" {
					allowed = true
					break
				}
			}
			if !allowed {
				c.JSON(403, gin.H{"error": "IP not allowed"})
				c.Abort()
				return
			}
		}
	}
	
	c.Set("user", user)
	c.Next()
}

func (p *ProxyServer) rateLimitMiddleware(c *gin.Context) {
	user := c.MustGet("user").(User)
	
	p.mu.Lock()
	limiter, exists := p.limiters[user.ID]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(time.Minute/100), 100)
		p.limiters[user.ID] = limiter
	}
	p.mu.Unlock()
	
	if !limiter.Allow() {
		c.JSON(429, gin.H{"error": "Rate limit exceeded"})
		c.Abort()
		return
	}
	
	c.Next()
}

func (p *ProxyServer) handleProxy(c *gin.Context) {
	service := c.Param("service")
	path := c.Param("path")
	user := c.MustGet("user").(User)
	
	// Get service config
	var baseURL, authHeader, authScheme, encryptedKey string
	err := p.db.QueryRow("SELECT base_url, auth_header, auth_scheme, encrypted_api_key FROM services WHERE name = ?", 
		service).Scan(&baseURL, &authHeader, &authScheme, &encryptedKey)
	
	if err != nil {
		c.JSON(400, gin.H{"error": "Service not supported"})
		return
	}
	
	if encryptedKey == "" {
		c.JSON(400, gin.H{"error": "No API key configured"})
		return
	}
	
	// Decrypt API key
	apiKey, err := decrypt(encryptedKey, p.masterKey)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to decrypt API key"})
		return
	}
	
	// Setup proxy
	target, _ := url.Parse(baseURL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = path
		req.Host = target.Host
		
		// Remove our auth header
		req.Header.Del("Authorization")
		
		// Set service auth header
		if authScheme == "" {
			req.Header.Set(authHeader, string(apiKey))
		} else {
			req.Header.Set(authHeader, fmt.Sprintf("%s %s", authScheme, string(apiKey)))
		}
	}
	
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("X-Secured-By", "SecureProxy")
		return nil
	}
	
	fmt.Printf("🔐 %s -> %s%s\n", user.Email, service, path)
	proxy.ServeHTTP(c.Writer, c.Request)
}

// ============================================================================
// CLI COMMANDS
// ============================================================================

func addService(name, baseURL, authHeader, authScheme, apiKey string) error {
	server, err := NewProxyServer()
	if err != nil {
		return err
	}
	defer server.db.Close()
	
	encryptedKey, err := encrypt([]byte(apiKey), server.masterKey)
	if err != nil {
		return err
	}
	
	_, err = server.db.Exec(`INSERT INTO services (name, base_url, auth_header, auth_scheme, encrypted_api_key)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET
		base_url=excluded.base_url, auth_header=excluded.auth_header, 
		auth_scheme=excluded.auth_scheme, encrypted_api_key=excluded.encrypted_api_key`,
		name, baseURL, authHeader, authScheme, encryptedKey)
	
	return err
}

func addUser(email string, allowedIPs []string) (string, error) {
	server, err := NewProxyServer()
	if err != nil {
		return "", err
	}
	defer server.db.Close()
	
	// Generate token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	
	// Hash token
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashStr := base64.StdEncoding.EncodeToString(tokenHash[:])
	
	ipsJSON, _ := json.Marshal(allowedIPs)
	userID := fmt.Sprintf("user_%d", time.Now().Unix())
	
	_, err = server.db.Exec("INSERT INTO users (id, email, token_hash, allowed_ips, created_at) VALUES (?, ?, ?, ?, ?)",
		userID, email, tokenHashStr, string(ipsJSON), time.Now())
	
	return token, err
}

func listConfig() error {
	server, err := NewProxyServer()
	if err != nil {
		return err
	}
	defer server.db.Close()
	
	fmt.Println("🔑 Services:")
	rows, _ := server.db.Query("SELECT name, base_url FROM services WHERE encrypted_api_key != ''")
	defer rows.Close()
	for rows.Next() {
		var name, baseURL string
		rows.Scan(&name, &baseURL)
		fmt.Printf("  ✅ %s -> %s\n", name, baseURL)
	}
	
	fmt.Println("\n👥 Users:")
	rows, _ = server.db.Query("SELECT email, allowed_ips FROM users")
	defer rows.Close()
	for rows.Next() {
		var email, ips string
		rows.Scan(&email, &ips)
		fmt.Printf("  - %s (IPs: %s)\n", email, ips)
	}
	
	return nil
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: secureproxy <command>")
		fmt.Println("Commands:")
		fmt.Println("  start                                    - Start proxy server")
		fmt.Println("  add <service> <api-key>                  - Add API key for default service")
		fmt.Println("  add-service <name> <url> <header> <scheme> <key> - Add custom service")
		fmt.Println("  user <email> [ip1,ip2]                   - Add user")
		fmt.Println("  list                                     - List configuration")
		return
	}
	
	command := os.Args[1]
	
	switch command {
	case "start":
		server, err := NewProxyServer()
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			return
		}
		defer server.db.Close()
		server.Start()
		
	case "add":
		if len(os.Args) < 4 {
			fmt.Println("Usage: secureproxy add <service> <api-key>")
			return
		}
		
		// Quick add for default services
		service := os.Args[2]
		apiKey := os.Args[3]
		
		server, _ := NewProxyServer()
		defer server.db.Close()
		
		encryptedKey, _ := encrypt([]byte(apiKey), server.masterKey)
		_, err := server.db.Exec("UPDATE services SET encrypted_api_key = ? WHERE name = ?", encryptedKey, service)
		
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
		} else {
			fmt.Printf("✅ Added API key for %s\n", service)
		}
		
	case "add-service":
		if len(os.Args) < 7 {
			fmt.Println("Usage: secureproxy add-service <name> <url> <header> <scheme> <key>")
			return
		}
		err := addService(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6])
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
		} else {
			fmt.Printf("✅ Service '%s' added\n", os.Args[2])
		}
		
	case "user":
		if len(os.Args) < 3 {
			fmt.Println("Usage: secureproxy user <email> [ip1,ip2]")
			return
		}
		
		var allowedIPs []string
		if len(os.Args) > 3 {
			allowedIPs = strings.Split(os.Args[3], ",")
		}
		
		token, err := addUser(os.Args[2], allowedIPs)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
		} else {
			fmt.Printf("✅ User created: %s\n", os.Args[2])
			fmt.Printf("🔑 Token: %s\n\n", token)
			fmt.Println("Usage examples:")
			fmt.Printf("curl -H 'Authorization: Bearer %s' http://localhost:8080/proxy/openai/v1/models\n", token)
			fmt.Printf("export OPENAI_API_KEY=%s\n", token)
			fmt.Printf("export OPENAI_BASE_URL=http://localhost:8080/proxy/openai\n")
		}
		
	case "list":
		err := listConfig()
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
		}
		
	default:
		fmt.Printf("❌ Unknown command: %s\n", command)
	}
}
