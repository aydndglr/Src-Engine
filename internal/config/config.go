package config

import (
	"time"
)

// --- SABİTLER ---

const (
	// Uygulama Bilgileri
	AppName    = "SRC-Engine"
	AppVersion = "2.0.0"

	// Port Yapılandırması (Sanal Portlar)
	PortControl = 9000 // Kimlik doğrulama, ayarlar, heartbeat
	PortStream  = 9001 // Video + Input (Düşük gecikme)
	PortAudio   = 9002 // Ses akışı
	PortFile    = 9003 // Dosya transferi
	PortChat    = 9004 // Metin mesajlaşması

	// Headscale / Tailscale Ayarları
	DefaultControlURL = "https://vpn.cybervpn.tr" // Senin sunucun
	TunNamePrefix     = "src-engine-"
)

// --- YAPILANDIRMA YAPILARI ---

type Config struct {
	DeviceID string // HWID veya Hostname
	AuthKey  string // Headscale Pre-Auth Key (Aynı zamanda LİSANS anahtarı)
	Video    VideoConfig
	Network  NetworkConfig
}

type NetworkConfig struct {
	ControlURL string
	Hostname   string
	DataDir    string // .src-engine klasörü
	LogEnabled bool
	ConnectIP  string // Client Modu için Hedef IP (Boşsa Host Modu)
}

type VideoConfig struct {
	Width   int
	Height  int
	FPS     int
	Bitrate int // kbps
	RawMode bool
}

// DefaultConfig: Varsayılan ayarları döndürür
func NewDefaultConfig() *Config {
	return &Config{
		Network: NetworkConfig{
			ControlURL: DefaultControlURL,
			LogEnabled: true,
		},
		Video: VideoConfig{
			Width:   0,  // 0 = Native
			Height:  0,  // 0 = Native
			FPS:     25, // Standart
			Bitrate: 1800,
			RawMode: false,
		},
	}
}

// Timeout Ayarları
const (
	ConnectTimeout = 30 * time.Second // Hızlı fail etmesi için süre kısaltıldı
	WriteTimeout   = 5 * time.Second
	ReadTimeout    = 10 * time.Second
	KeepAlive      = 10 * time.Second
)