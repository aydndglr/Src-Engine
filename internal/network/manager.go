package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"src-engine-v2/internal/config"
	"time"

	"tailscale.com/tsnet"
)

// Manager: Headscale/Tailscale bağlantısını ve port yönetimini sağlar.
type Manager struct {
	Server *tsnet.Server
	Conf   *config.Config
	MyIP   string
}

// NewManager: Yeni bir ağ yöneticisi oluşturur.
func NewManager(cfg *config.Config) *Manager {
	// Durum dosyaları için klasör yolu (~/.src-engine/hostname)
	homeDir, _ := os.UserHomeDir()
	if cfg.Network.DataDir == "" {
		cfg.Network.DataDir = filepath.Join(homeDir, ".src-engine", cfg.Network.Hostname)
	}
	_ = os.MkdirAll(cfg.Network.DataDir, 0700)

	s := &tsnet.Server{
		Hostname:   cfg.Network.Hostname,
		AuthKey:    cfg.AuthKey,
		ControlURL: cfg.Network.ControlURL,
		Dir:        cfg.Network.DataDir,
		Logf: func(format string, args ...any) {
			if cfg.Network.LogEnabled {
				//log.Printf("[TSNET] "+format, args...)
			}
		},
	}

	return &Manager{
		Server: s,
		Conf:   cfg,
	}
}

// Start: VPN ağına bağlanır ve hazır olana kadar bekler.
func (m *Manager) Start(ctx context.Context) error {
	// Motoru tetiklemek için sahte bir dinleyici açıp kapatıyoruz (Kickstart)
	ln, err := m.Server.Listen("tcp", ":0")
	if err == nil {
		ln.Close()
	}

	lc, err := m.Server.LocalClient()
	if err != nil {
		return fmt.Errorf("local client hatası: %v", err)
	}

	fmt.Println("⏳ VPN Ağına Bağlanılıyor...")

	// Hazır Olana Kadar Bekle (Timeout config'den gelir)
	timeoutCtx, cancel := context.WithTimeout(ctx, config.ConnectTimeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("zaman aşımı: VPN bağlantısı kurulamadı")
		case <-ticker.C:
			st, err := lc.Status(ctx)
			if err != nil {
				continue
			}

			// BackendState "Running" olmalı
			if st.BackendState == "Running" {
				for _, ip := range st.TailscaleIPs {
					if ip.Is4() {
						m.MyIP = ip.String()
						fmt.Printf("✅ VPN Tüneli Kurulu! IP: %s\n", m.MyIP)
						return nil
					}
				}
			}
		}
	}
}

// Listen: Belirtilen portu dinlemeye başlar (Sunucu Modu).
func (m *Manager) Listen(port int) (net.Listener, error) {
	return m.Server.Listen("tcp", fmt.Sprintf(":%d", port))
}

// Dial: Hedef IP ve Porta bağlanır (İstemci Modu).
func (m *Manager) Dial(ctx context.Context, targetIP string, port int) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, config.ConnectTimeout)
	defer cancel()

	conn, err := m.Server.Dial(dialCtx, "tcp", fmt.Sprintf("%s:%d", targetIP, port))
	if err != nil {
		return nil, err
	}

	// 🔥 NETWORK BOOST: Tampon Ayarları
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(config.KeepAlive)
		
		// 1 MB Tampon (Veri şişmesini önler)
		_ = tcpConn.SetWriteBuffer(128 * 1024)
		_ = tcpConn.SetReadBuffer(128 * 1024)
		_ = tcpConn.SetNoDelay(true)
	}

	return conn, nil
}