package main

import (
	"flag"
	"os"
	"src-engine-v2/internal/config"
	"src-engine-v2/internal/core"
)

// Senin oluşturduğun 10 yıllık genel key (Ücretsiz Mod İçin)
const DefaultFreeKey = "b8a9818f518d3f98700d91507efe87caa88b48586ebcf099"

func main() {
	// Sistem adını otomatik al
	sysHostname, _ := os.Hostname()
	if sysHostname == "" {
		sysHostname = "src-engine-client"
	}

	// Parametreleri al
	hostname := flag.String("host", sysHostname, "Cihaz Adı (Varsayılan: Bilgisayar Adı)")
	authKey := flag.String("key", "", "Headscale Auth Key (Boş bırakılırsa 120 dk Ücretsiz Mod)")
	
	// 🆕 YENİ PARAMETRE: Client Modu için Hedef IP
	connectIP := flag.String("connect", "", "Bağlanılacak Hedef IP (Client Modu)")

	// Video Ayarları
	width := flag.Int("w", 0, "Genişlik (0=Oto)")
	height := flag.Int("h", 0, "Yükseklik (0=Oto)")
	fps := flag.Int("fps", 25, "FPS")
	
	// Raw Mod (VLC vb. için headersız yayın)
	raw := flag.Bool("raw", false, "Ham video modu (VLC uyumlu)")

	flag.Parse()

	// Ayarları Hazırla
	cfg := config.NewDefaultConfig()
	cfg.Network.Hostname = *hostname
	cfg.Network.ConnectIP = *connectIP // 🆕 Config'e eklendi
	cfg.Video.Width = *width
	cfg.Video.Height = *height
	cfg.Video.FPS = *fps
	cfg.Video.RawMode = *raw

	// Lisans ve Deneme Modu Mantığı
	if *authKey == "" {
		// Key girilmemiş -> Ücretsiz Deneme Modu (Default Key Kullanılır)
		cfg.AuthKey = DefaultFreeKey
		// Core katmanına deneme modu olduğunu bildiriyoruz
		os.Setenv("SRC_TRIAL_MODE", "1") 
	} else {
		// Key girilmiş -> Premium Mod (Süre sınırını Headscale/Sunucu yönetir)
		cfg.AuthKey = *authKey
		os.Setenv("SRC_TRIAL_MODE", "0")
	}

	// Uygulamayı Oluştur ve Başlat
	app := core.NewApp(cfg)
	app.Run()
}