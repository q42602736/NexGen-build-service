package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

//go:embed web
var webFS embed.FS

type Config struct {
	Port                string
	ListenHost          string
	SourceToken         string
	BuildToken          string
	GithubOwner         string
	GithubRepo          string
	GithubBranch        string
	GithubProfileBranch string
	BuildOwner          string
	BuildRepo           string
	XrayBuildOwner      string
	XrayBuildRepo       string
	NexGenBuildOwner    string
	NexGenBuildRepo     string
	NexGenProfileBranch string
	BuildEventToken     string
	GitHubWebhookSecret string
	JWTSecret           string
	AdminPassword       string
	ConfigFilepath      string
}

var cfg Config

func loadConfig() {
	cfg = Config{
		Port:                getEnv("PORT", "8080"),
		ListenHost:          getEnv("LISTEN_HOST", "127.0.0.1"),
		SourceToken:         mustEnv("SOURCE_TOKEN"),
		BuildToken:          mustEnv("BUILD_TOKEN"),
		GithubOwner:         mustEnv("GITHUB_OWNER"),
		GithubRepo:          mustEnv("GITHUB_REPO"),
		GithubBranch:        getEnv("GITHUB_BRANCH", "main"),
		GithubProfileBranch: getEnv("GITHUB_PROFILE_BRANCH", ""),
		BuildOwner:          getEnv("BUILD_OWNER", ""),
		BuildRepo:           getEnv("BUILD_REPO", ""),
		XrayBuildOwner:      getEnv("XRAY_BUILD_OWNER", "q42602736"),
		XrayBuildRepo:       getEnv("XRAY_BUILD_REPO", "NexGen-client-xray"),
		NexGenBuildOwner:    getEnv("NEXGEN_BUILD_OWNER", "q42602736"),
		NexGenBuildRepo:     getEnv("NEXGEN_BUILD_REPO", "NexGen-client-React"),
		NexGenProfileBranch: getEnv("NEXGEN_PROFILE_BRANCH", "profiles"),
		BuildEventToken:     getEnv("BUILD_EVENT_TOKEN", ""),
		GitHubWebhookSecret: getEnv("GITHUB_WEBHOOK_SECRET", ""),
		JWTSecret:           getEnv("JWT_SECRET", ""),
		AdminPassword:       getEnv("ADMIN_PASSWORD", ""),
		ConfigFilepath:      getEnv("CONFIG_FILEPATH", "assets/config/xboard.config.yaml"),
	}
	cfg.JWTSecret = mustEnv("JWT_SECRET")
	cfg.AdminPassword = mustEnv("ADMIN_PASSWORD")
	// 配置只来自专用构建，清除可能由启动器继承的旧凭证变量。
	for _, key := range []string{"GITHUB_TOKEN", "SOURCE_TOKEN", "SOURCE_READ_TOKEN", "PROFILE_WRITE_TOKEN", "BUILD_TOKEN", "JWT_SECRET", "ADMIN_PASSWORD", "BUILD_EVENT_TOKEN", "GITHUB_WEBHOOK_SECRET", "SECURE_LOG_PRIVATE_KEY", "DATABASE_ENCRYPTION_KEY"} {
		os.Unsetenv(key)
	}

	if cfg.BuildOwner == "" {
		cfg.BuildOwner = cfg.GithubOwner
	}
	if cfg.BuildRepo == "" {
		cfg.BuildRepo = "Xboard-Mihomo-builds"
	}
	if cfg.XrayBuildOwner == "" {
		cfg.XrayBuildOwner = cfg.BuildOwner
	}
	if cfg.NexGenBuildOwner == "" {
		cfg.NexGenBuildOwner = cfg.BuildOwner
	}
	if cfg.GithubProfileBranch == "" {
		cfg.GithubProfileBranch = cfg.GithubBranch
	}
	if cfg.NexGenProfileBranch == "" {
		cfg.NexGenProfileBranch = cfg.GithubProfileBranch
	}
}

func getEnv(key, fallback string) string {
	if v := embeddedEnvironment[key]; v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := embeddedEnvironment[key]
	if v == "" {
		log.Fatalf("专用二进制缺少内置配置 %s，请重新构建", key)
	}
	return v
}

func main() {
	// 数据库、WAL 和共享内存文件默认仅允许服务账户读写。
	syscall.Umask(0077)
	loadConfig()
	if _, err := databaseEncryptionKey(); err != nil {
		log.Fatal(err)
	}
	if len(os.Args) == 2 && os.Args[1] == "--check-config" {
		if _, err := loadSecureLogPrivateKey(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("内置配置、数据库密钥及日志私钥检查通过")
		return
	}
	if len(os.Args) > 1 {
		if err := runDatabaseCommand(os.Args[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	initDB()

	gh := NewGitHubClient(
		cfg.SourceToken,
		cfg.GithubOwner,
		cfg.GithubRepo,
		cfg.GithubBranch,
	)
	profileGH := NewGitHubClient(
		cfg.SourceToken,
		cfg.GithubOwner,
		cfg.GithubRepo,
		cfg.GithubProfileBranch,
	)
	nexGenProfileGH := NewGitHubClient(
		cfg.SourceToken,
		cfg.NexGenBuildOwner,
		cfg.NexGenBuildRepo,
		cfg.NexGenProfileBranch,
	)
	buildGH := NewGitHubClient(cfg.BuildToken, cfg.BuildOwner, cfg.BuildRepo, "main")
	h := NewHandlers(gh, profileGH, nexGenProfileGH, buildGH)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// 认证接口（公开）
	r.Post("/api/auth/login", h.Login)
	r.Post("/api/auth/admin", h.AdminLogin)
	r.Post("/api/internal/build-events/bind", h.InternalBindBuildRun)
	r.Post("/api/internal/build-events/progress", h.InternalUpdateBuildProgress)
	r.Post("/api/internal/build-events/complete", h.InternalCompleteBuildRun)
	r.Post("/api/internal/github/webhook", h.HandleGitHubWebhook)
	r.Get("/download/build/records/{id}/assets/{assetID}", h.DownloadBuildRecordAssetByToken)
	r.Get("/profile-assets/history/{id}", h.GetProfileAsset)

	// 需要登录的 API
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware)

		r.Get("/api/auth/me", h.GetCurrentUserInfo)
		r.Get("/api/profiles", h.ListProfiles)
		r.Get("/api/profiles/{name}", h.GetProfile)
		r.Post("/api/custom-features/ui-colors/load", h.GetPublicUIColorCustomConfig)
		r.Put("/api/custom-features/ui-colors", h.SavePublicUIColorCustomConfig)
		r.Put("/api/profiles/{name}", h.SaveProfile)
		r.Post("/api/profiles/{name}/assets/{kind}", h.UploadProfileAsset)
		r.Get("/api/profile-assets/history", h.ListProfileAssetHistory)
		r.Delete("/api/profile-assets/history/{id}", h.DeleteProfileAssetHistory)
		r.Delete("/api/profiles/{name}", h.DeleteProfile)
		r.Get("/api/branches", h.ListBranches)
		r.Post("/api/build/trigger", h.TriggerBuild)
		r.Get("/api/build/history", h.GetBuildHistory)
		r.Get("/api/build/records", h.ListBuildRecords)
		r.Post("/api/build/records/{id}/cancel", h.CancelBuildRecord)
		r.Delete("/api/build/records/{id}", h.DeleteBuildRecord)
		r.Get("/api/build/records/{id}/assets", h.GetBuildRecordAssets)
		r.Post("/api/build/records/{id}/download/{assetID}/link", h.CreateBuildRecordAssetDownloadLink)
		r.Get("/api/build/records/{id}/download/{assetID}", h.DownloadBuildRecordAsset)
		r.Get("/api/build/queue", h.GetBuildQueue)
		r.Get("/api/build/status", h.GetBuildStatus)
		r.Get("/api/client-updates", h.GetClientUpdates)
		r.Post("/api/client-proxy/parse", h.ParseClientProxyLinks)
		r.Post("/api/subscription/parse", h.ParseSubscriptionLinks)
		r.Post("/api/secure-logs/decrypt", h.DecryptSecureLog)
	})

	// 管理员 API
	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware)
		r.Use(AdminMiddleware)

		r.Get("/api/admin/codes", h.ListCodes)
		r.Post("/api/admin/codes", h.CreateCode)
		r.Put("/api/admin/codes/batch/clients", h.BatchUpdateCodeClients)
		r.Put("/api/admin/codes/{id}/status", h.SetActivationCodeStatus)
		r.Put("/api/admin/codes/{id}", h.UpdateCode)
		r.Delete("/api/admin/codes/{id}", h.DeleteCode)
		r.Get("/api/admin/build-records", h.ListAdminBuildRecords)
		r.Get("/api/admin/build-records/{id}/oss-diff", h.GetAdminBuildRecordOSSCompare)
		r.Put("/api/admin/profiles/{name}/rename", h.RenameProfile)
		r.Get("/api/admin/github/api-stats", h.GetGitHubAPIStats)
		r.Get("/api/admin/profiles/duplicates", h.ListDuplicateProfiles)
		r.Get("/api/admin/logs", h.GetAuditLogs)
		r.Get("/api/admin/settings", h.GetSystemSettings)
		r.Put("/api/admin/settings", h.SaveSystemSettings)
	})

	// 静态文件（前端页面）
	webContent, _ := fs.Sub(webFS, "web")
	fileServer := http.FileServer(http.FS(webContent))
	r.Handle("/*", fileServer)

	addr := net.JoinHostPort(cfg.ListenHost, cfg.Port)
	fmt.Printf("NexGen Client 配置服务器已启动：http://%s\n", addr)
	server := &http.Server{Addr: addr, Handler: r, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}
