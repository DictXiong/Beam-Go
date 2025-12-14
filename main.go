package main

import (
	"archive/zip"
	"crypto/rand"
	"database/sql"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/rpc"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed templates/*
var content embed.FS

const (
	CodeLen       = 6
	CodeLetters   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	DefaultSocket = "/var/run/beam-go.sock"
)

// ================= RPC Definitions =================

type RPCShare struct {
	Code      string
	LocalPath string
	ExpiresAt time.Time
	IsDir     bool
}

type AddArgs struct {
	Path string
	Days int
}

type DelArgs struct {
	Code string
	Path string
}

type EmptyArgs struct{}

type BeamRPC struct{}

// ================= Global State =================

var (
	db      *sql.DB
	webRoot string
)

// ================= Utils =================

func initDB(dir string) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("无法创建数据库目录: %v", err)
	}
	dbFile := filepath.Join(dir, "data.db")
	var err error
	db, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatal(err)
	}

	db.SetMaxOpenConns(1)

	query := `CREATE TABLE IF NOT EXISTS shares (
		code TEXT PRIMARY KEY,
		local_path TEXT,
		created_at DATETIME,
		expires_at DATETIME
	);`
	if _, err = db.Exec(query); err != nil {
		log.Fatal(err)
	}
	log.Printf("📦 数据库已加载: %s", dbFile)
}

func generateCode(n int) (string, error) {
	b := make([]byte, n)
	for {
		for i := range b {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(CodeLetters))))
			if err != nil {
				return "", err
			}
			b[i] = CodeLetters[num.Int64()]
		}
		var exists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM shares WHERE code = ?)", string(b)).Scan(&exists)
		if err != nil {
			log.Fatal(err)
		}
		if !exists {
			return string(b), nil
		}
	}
}

func formatSize(size int64) string {
	if size > 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", float64(size)/1024/1024/1024)
	}
	if size > 1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(size)/1024/1024)
	}
	if size > 1024 {
		return fmt.Sprintf("%.2f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%d B", size)
}

func resolvePath(basePath, subPath string) (string, error) {
	realBase, err := filepath.EvalSymlinks(basePath)
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(realBase, subPath)
	realFull, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(realFull, realBase) {
		return "", fmt.Errorf("access denied: symlink points outside base")
	}

	return realFull, nil
}

func getRealIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	addr, _ := netip.ParseAddr(ip)
	if addr.IsLoopback() || addr.IsPrivate() {
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return ip
		}
		if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			parts := strings.Split(ip, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	return ip
}

// ================= RPC Implementation =================

func (s *BeamRPC) Add(args AddArgs, reply *RPCShare) error {
	info, err := os.Stat(args.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("服务端无法找到该路径")
		}
		return fmt.Errorf("服务端无法访问该路径 (权限不足?): %v", err)
	}

	code, err := generateCode(CodeLen)
	if err != nil {
		return err
	}
	expiresAt := time.Now().Add(time.Duration(args.Days) * 24 * time.Hour)

	_, err = db.Exec("INSERT INTO shares (code, local_path, created_at, expires_at) VALUES (?, ?, ?, ?)",
		code, args.Path, time.Now(), expiresAt)
	if err != nil {
		return err
	}

	*reply = RPCShare{
		Code:      code,
		LocalPath: args.Path,
		ExpiresAt: expiresAt,
		IsDir:     info.IsDir(),
	}
	log.Printf("RPC Add: Code=%s Path=%s ExpiresAt=%s", code, args.Path, expiresAt.Format(time.RFC3339))
	return nil
}

func (s *BeamRPC) List(args EmptyArgs, reply *[]RPCShare) error {
	rows, err := db.Query("SELECT code, local_path, expires_at FROM shares ORDER BY created_at DESC")
	if err != nil {
		return err
	}
	defer rows.Close()

	var shares []RPCShare
	for rows.Next() {
		var s RPCShare
		rows.Scan(&s.Code, &s.LocalPath, &s.ExpiresAt)
		shares = append(shares, s)
	}
	*reply = shares
	return nil
}

func (s *BeamRPC) Del(args DelArgs, reply *int) error {
	var res sql.Result
	var err error
	if args.Code != "" {
		res, err = db.Exec("DELETE FROM shares WHERE code = ?", args.Code)
		if err != nil {
			return err
		}
	} else if args.Path != "" {
		res, err = db.Exec("DELETE FROM shares WHERE local_path = ?", args.Path)
		if err != nil {
			return err
		}
	}

	affected, _ := res.RowsAffected()
	*reply = int(affected)
	log.Printf("RPC Del: Code=%s Path=%s Deleted=%v", args.Code, args.Path, *reply)
	return nil
}

// ================= HTTP Handlers =================

type RateLimiter struct {
	visitors  map[string]int
	mu        sync.Mutex
	lastReset time.Time
}

var (
	limiter    = &RateLimiter{visitors: make(map[string]int), lastReset: time.Now()}
	tmpl404    = template.Must(template.ParseFS(content, "templates/404.html"))
	tmplIndex  = template.Must(template.ParseFS(content, "templates/index.html"))
	tmplBrowse = template.Must(template.ParseFS(content, "templates/browse.html"))
)

func (l *RateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.lastReset) > 10*time.Minute {
		clear(l.visitors)
		l.lastReset = time.Now()
	}
	if l.visitors[ip] > 20 {
		return false
	}
	l.visitors[ip]++
	return true
}

func (l *RateLimiter) Pass(ip string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.visitors, ip)
	return nil
}

func render404(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	data := struct {
		WebRoot string
	}{WebRoot: webRoot}
	tmpl404.Execute(w, data)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != webRoot {
		render404(w)
		return
	}
	tmplIndex.Execute(w, nil)
}

func handleShare(w http.ResponseWriter, r *http.Request) {
	ip := getRealIP(r)
	if !limiter.Allow(ip) {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, webRoot+"s/"), "/")
	if len(parts) == 0 {
		render404(w)
		return
	}
	code := parts[0]
	subPath := strings.Join(parts[1:], "/")
	if subPath == "" && !strings.HasSuffix(r.URL.Path, "/") {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusFound)
		return
	}
	for _, i := range code {
		if !(i >= 'a' && i <= 'z' || i >= 'A' && i <= 'Z' || i >= '0' && i <= '9') {
			render404(w)
			return
		}
	}

	var localPath string
	var expiresAt time.Time
	err := db.QueryRow("SELECT local_path, expires_at FROM shares WHERE code = ?", code).Scan(&localPath, &expiresAt)

	if err == sql.ErrNoRows || time.Now().After(expiresAt) {
		render404(w)
		return
	}
	limiter.Pass(ip)

	info, err := os.Stat(localPath)
	if err != nil {
		render404(w)
		return
	}

	// === 单文件模式 ===
	if !info.IsDir() {
		if subPath == "" {
			item := struct {
				Name, Size, Path string
				IsDir            bool
			}{
				Name:  info.Name(),
				IsDir: false,
				Size:  formatSize(info.Size()),
				Path:  info.Name(),
			}
			data := struct {
				Code, Path string
				Items      []struct {
					Name, Size, Path string
					IsDir            bool
				}
				IsSingleFile bool
				WebRoot      string
			}{
				Code: code, Path: "", Items: []struct {
					Name, Size, Path string
					IsDir            bool
				}{item}, IsSingleFile: true,
				WebRoot: webRoot,
			}
			tmplBrowse.Execute(w, data)
			return
		}
		if subPath == info.Name() {
			http.ServeFile(w, r, localPath)
			return
		}
		render404(w)
		return
	}

	// === 目录模式 ===
	realPath, err := resolvePath(localPath, subPath)
	if err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	fileInfo, err := os.Stat(realPath)
	if err != nil {
		render404(w)
		return
	}

	// 无论是根目录还是子目录，如果是文件夹，都可以 Zip 下载
	if fileInfo.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusFound)
			return
		}
		if r.URL.Query().Get("action") == "zip" {
			streamZip(w, r, realPath)
			return
		}

		files, _ := os.ReadDir(realPath)
		type FileItem struct {
			Name, Size, Path string
			IsDir            bool
		}
		var items []FileItem

		if subPath != "" {
			items = append(items, FileItem{Name: ".. (上级)", IsDir: true, Path: ".."})
		}

		for _, f := range files {
			if strings.HasPrefix(f.Name(), ".") {
				continue
			}
			size := "-"
			if !f.IsDir() {
				info, _ := f.Info()
				size = formatSize(info.Size())
			}
			items = append(items, FileItem{Name: f.Name(), IsDir: f.IsDir(), Size: size, Path: f.Name()})
		}

		// IsSingleFile = false，所以前端会显示 ZIP 按钮
		tmplBrowse.Execute(w, struct {
			Code, Path   string
			Items        []FileItem
			IsSingleFile bool
			WebRoot      string
		}{code, subPath, items, false, webRoot})
		return
	}

	http.ServeFile(w, r, realPath)
}

func streamZip(w http.ResponseWriter, r *http.Request, basePath string) {
	dirName := filepath.Base(basePath)
	// 避免子目录名为 "." 或 "/"
	if dirName == "." || dirName == "/" {
		log.Printf("Invalid directory name given to streamZip: %s", basePath)
		return
	}

	encodedName := url.PathEscape(dirName)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.zip\"; filename*=UTF-8''%s.zip", encodedName, encodedName))

	zw := zip.NewWriter(w)
	defer zw.Close()

	filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if r.Context().Err() != nil {
			return r.Context().Err()
		}
		if err != nil || (!info.IsDir() && strings.HasPrefix(info.Name(), ".")) || (info.Mode()&os.ModeSymlink != 0) {
			return nil
		}
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(basePath, path)
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		h, _ := zip.FileInfoHeader(info)
		h.Name = rel
		h.Method = zip.Deflate
		if info.IsDir() {
			h.Name += "/"
			zw.CreateHeader(h)
		} else {
			wtr, _ := zw.CreateHeader(h)
			f, err := os.Open(path)
			if err != nil {
				log.Printf("Failed to open file for zipping: %v", err)
				return nil
			}
			defer f.Close()
			io.Copy(wtr, f)
		}
		return nil
	})
}

// ================= Command Implementations =================

// registerSocketFlag 辅助函数，给所有子命令注册 -s
func registerSocketFlag(fs *flag.FlagSet, socketPtr *string) {
	fs.StringVar(socketPtr, "s", DefaultSocket, "Socket path")
	fs.StringVar(socketPtr, "socket", DefaultSocket, "Socket path")
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var dir, port, socketPath, subpath string
	fs.StringVar(&dir, "d", "", "DB Dir (Required)")
	fs.StringVar(&dir, "database", "", "DB Dir")
	fs.StringVar(&port, "p", ":8280", "Port")
	fs.StringVar(&port, "port", ":8280", "Port")
	fs.StringVar(&subpath, "subpath", "", "Subpath")
	registerSocketFlag(fs, &socketPath)

	fs.Parse(args)

	if dir == "" {
		fmt.Println("❌ 错误: 必须指定数据库目录 (-d)")
		os.Exit(1)
	}

	initDB(dir)

	// 清理旧的 Socket
	if _, err := os.Stat(socketPath); err == nil {
		os.Remove(socketPath)
	}

	rpcShare := new(BeamRPC)
	rpc.Register(rpcShare)

	sockListener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("❌ Socket 监听失败: %v\n(提示: %s 通常需要 root 权限，请尝试 sudo 或使用 -s /tmp/beam.sock)", err, socketPath)
	}
	os.Chmod(socketPath, 0600)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n正在关闭...")
		os.Remove(socketPath)
		db.Close()
		os.Exit(0)
	}()

	go func() {
		for {
			conn, err := sockListener.Accept()
			if err != nil {
				continue
			}
			go rpc.ServeConn(conn)
		}
	}()

	if subpath == "" || subpath == "/" {
		webRoot = "/"
	} else {
		webRoot = "/" + strings.Trim(subpath, "/") + "/"
	}
	apiMux := http.NewServeMux()
	apiMux.HandleFunc(webRoot, handleIndex)
	apiMux.HandleFunc(webRoot+"s/", handleShare)

	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("⚡️ BEAM SERVER STARTED\n")
	fmt.Printf("📂 Database: %s\n", dir)
	fmt.Printf("🔌 Socket:   %s\n", socketPath)
	fmt.Printf("🌍 HTTP:     http://%s%s\n", port, webRoot)
	fmt.Println(strings.Repeat("=", 50))

	server := &http.Server{
		Addr:         port,
		Handler:      apiMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func cmdAdd(args []string) {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	var socketPath string
	var days int
	fs.IntVar(&days, "d", 7, "days")
	fs.IntVar(&days, "days", 7, "days")
	registerSocketFlag(fs, &socketPath)

	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Println("用法: beam add [-d days] [-s socket] <path>")
		return
	}
	path := fs.Arg(0)
	absPath, _ := filepath.Abs(path)
	if days == 0 {
		days = 36500
	}

	client, err := rpc.Dial("unix", socketPath)
	if err != nil {
		fmt.Printf("❌ 无法连接到服务 (%s): %v\n", socketPath, err)
		return
	}
	defer client.Close()

	var reply RPCShare
	if err := client.Call("BeamRPC.Add", AddArgs{Path: absPath, Days: days}, &reply); err != nil {
		fmt.Println("❌ 添加失败:", err)
		return
	}

	typeStr := "文件"
	if reply.IsDir {
		typeStr = "目录"
	}
	fmt.Printf("\n✅ 分享成功\nCode:   %s\nPath:   %s\nType:   %s\nExpire: %s\n", reply.Code, reply.LocalPath, typeStr, reply.ExpiresAt.Format(time.RFC3339))
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var socketPath string
	var printAll bool
	fs.BoolVar(&printAll, "a", false, "Print all shares including expired ones")
	fs.BoolVar(&printAll, "all", false, "Print all shares including expired ones")
	registerSocketFlag(fs, &socketPath)
	fs.Parse(args)

	client, err := rpc.Dial("unix", socketPath)
	if err != nil {
		fmt.Printf("❌ 无法连接到服务 (%s): %v\n", socketPath, err)
		return
	}
	defer client.Close()

	var shares []RPCShare
	client.Call("BeamRPC.List", EmptyArgs{}, &shares)
	fmt.Printf("%-10s %-20s %s\n", "CODE", "EXPIRES", "PATH")
	fmt.Println(strings.Repeat("-", 60))
	var printingExpired bool
	for _, s := range shares {
		if !printingExpired && time.Now().After(s.ExpiresAt) {
			if !printAll {
				break
			}
			printingExpired = true
			fmt.Println("\n已过期的分享:")
		}
		fmt.Printf("%-10s %-20s %s\n", s.Code, s.ExpiresAt.Format("2006-01-02 15:04"), s.LocalPath)
	}
}

func cmdDel(args []string) {
	fs := flag.NewFlagSet("del", flag.ExitOnError)
	var socketPath, code string
	path := ""
	fs.StringVar(&code, "c", "", "Share code")
	fs.StringVar(&code, "code", "", "Share code")
	registerSocketFlag(fs, &socketPath)

	fs.Parse(args)

	if code == "" {
		if fs.NArg() != 1 {
			fmt.Println("用法: beam del path [-c code] [-s socket]")
			return
		}
		path, _ = filepath.Abs(fs.Arg(0))
	}

	client, err := rpc.Dial("unix", socketPath)
	if err != nil {
		fmt.Printf("❌ 无法连接到服务 (%s): %v\n", socketPath, err)
		return
	}
	defer client.Close()
	var affected int
	client.Call("BeamRPC.Del", DelArgs{Code: code, Path: path}, &affected)
	if affected > 0 {
		fmt.Printf("✅ 已删除 %d 条记录\n", affected)
	} else {
		fmt.Println("⚠️ 未找到或删除失败")
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Beam 文件分享系统")
		fmt.Println("用法: beam <serve|add|list|del> [options]")
		os.Exit(1)
	}

	// 提取 subcommand 和后续参数
	verb := os.Args[1]
	rest := os.Args[2:]

	switch verb {
	case "serve":
		cmdServe(rest)
	case "add":
		cmdAdd(rest)
	case "list":
		cmdList(rest)
	case "del":
		cmdDel(rest)
	default:
		fmt.Printf("未知命令: %s\n", verb)
		os.Exit(1)
	}
}
