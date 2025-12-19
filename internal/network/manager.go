/*
package network

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/tsnet"
)

// Manager: Headscale üzerinden TCP tüneli sağlar.
type Manager struct {
	Server *tsnet.Server
	MyIP   string
}

// NewManager: Yeni bir ağ yöneticisi oluşturur.
func NewManager(hostname, authKey, controlURL string) (*Manager, error) {
	homeDir, _ := os.UserHomeDir()
	stateDir := filepath.Join(homeDir, ".src-engine", hostname)
	_ = os.MkdirAll(stateDir, 0700)

	s := &tsnet.Server{
		Hostname:   hostname,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Dir:        stateDir,
		Logf: func(format string, args ...any) {
			log.Printf("[TSNET] "+format, args...)
		},
	}

	return &Manager{Server: s}, nil
}

// StartTunnel: VPN ağına bağlanır ve IP adresini alana kadar bekler.
func (m *Manager) StartTunnel() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Motoru tetiklemek için sahte bir dinleyici açıp kapatıyoruz
	ln, err := m.Server.Listen("tcp", ":0")
	if err == nil {
		ln.Close()
	}

	lc, err := m.Server.LocalClient()
	if err != nil {
		return fmt.Errorf("local client hatası: %v", err)
	}

	// IP adresi atanana kadar döngüde bekle
	for i := 0; i < 60; i++ {
		st, err := lc.Status(ctx)
		if err == nil {
			for _, ip := range st.TailscaleIPs {
				if ip.Is4() {
					m.MyIP = ip.String()
					return nil
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("zaman aşımı: IP alınamadı")
}

// ListenTCP: Host (Yayıncı) tarafı için güvenli TCP portu açar.
func (m *Manager) ListenTCP(port int) (net.Listener, error) {
	return m.Server.Listen("tcp", fmt.Sprintf(":%d", port))
}

// DialTCP: Client (İzleyici) tarafı için karşıya bağlanır.
// 🔥 GÜNCELLENDİ: Keep-Alive ayarı eklendi.
func (m *Manager) DialTCP(targetIP string, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // 30sn çok uzun, 10sn yeter
	defer cancel()

	conn, err := m.Server.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", targetIP, port))
	if err != nil {
		return nil, err
	}

	// TCP Keep-Alive Ayarı:
	// Bağlantı boşta kalsa bile her 10 saniyede bir "Ben buradayım" sinyali gönder.
	// Bu, modemlerin (NAT) bağlantıyı "Ölü" sanıp kesmesini engeller.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(10 * time.Second)
	}

	return conn, nil
}
	*/

package network

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/tsnet"
)

// Manager: Headscale üzerinden TCP tüneli sağlar.
type Manager struct {
	Server *tsnet.Server
	MyIP   string
}

// NewManager: Yeni bir ağ yöneticisi oluşturur.
func NewManager(hostname, authKey, controlURL string) (*Manager, error) {
	homeDir, _ := os.UserHomeDir()
	stateDir := filepath.Join(homeDir, ".src-engine", hostname)
	_ = os.MkdirAll(stateDir, 0700)

	s := &tsnet.Server{
		Hostname:   hostname,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Dir:        stateDir,
		Logf: func(format string, args ...any) {
			log.Printf("[TSNET] "+format, args...)
		},
	}

	return &Manager{Server: s}, nil
}

// StartTunnel: VPN ağına bağlanır ve IP adresini alana kadar bekler.
/*
func (m *Manager) StartTunnel() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Motoru tetiklemek için sahte bir dinleyici açıp kapatıyoruz
	ln, err := m.Server.Listen("tcp", ":0")
	if err == nil {
		ln.Close()
	}

	lc, err := m.Server.LocalClient()
	if err != nil {
		return fmt.Errorf("local client hatası: %v", err)
	}

	// IP adresi atanana kadar döngüde bekle
	for i := 0; i < 60; i++ {
		st, err := lc.Status(ctx)
		if err == nil {
			for _, ip := range st.TailscaleIPs {
				if ip.Is4() {
					m.MyIP = ip.String()
					return nil
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("zaman aşımı: IP alınamadı")
}
*/

// StartTunnel: VPN ağına bağlanır, IP adresini alana ve motor hazır olana kadar bekler.
func (m *Manager) StartTunnel() error {
	// Bağlantı süresini biraz esnek tutalım (60sn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. Motoru tetiklemek için sahte bir dinleyici açıp kapatıyoruz (Kickstart)
	ln, err := m.Server.Listen("tcp", ":0")
	if err == nil {
		ln.Close()
	}

	// 2. LocalClient (Motor ile konuşan ajan) oluştur
	lc, err := m.Server.LocalClient()
	if err != nil {
		return fmt.Errorf("local client hatası: %v", err)
	}

	fmt.Println("⏳ VPN Ağına Bağlanılıyor...")

	// 3. Hazır Olana Kadar Bekle (Loop)
	for i := 0; i < 60; i++ {
		st, err := lc.Status(ctx)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		// --- 🔥 SAĞLIK KONTROLÜ (Health Check) ---
		// Eğer UDP engellendiyse veya DERP hatası varsa burada yakalarız.
		if len(st.Health) > 0 {
			for _, warning := range st.Health {
				// Kritik uyarıları ekrana bas
				fmt.Printf("⚠️ AĞ UYARISI: %s\n", warning)
			}
		}

		// --- 🔥 DURUM KONTROLÜ ---
		// Sadece IP almak yetmez, BackendState "Running" olmalı.
		if st.BackendState == "Running" {
			for _, ip := range st.TailscaleIPs {
				if ip.Is4() {
					m.MyIP = ip.String()
					fmt.Printf("✅ VPN Tüneli Kurulu! Durum: %s\n", st.BackendState)
					
					// P2P mi Relay mi olduğunu anlamak için (Opsiyonel Bilgi)
					// DERPMap boş değilse ve Peer varsa loglarda görürüz.
					return nil
				}
			}
		}

		// Henüz hazır değilse bekle
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("zaman aşımı: VPN bağlantısı (Running) durumuna geçemedi")
}

// ListenTCP: Host (Yayıncı) tarafı için güvenli TCP portu açar.
func (m *Manager) ListenTCP(port int) (net.Listener, error) {
	return m.Server.Listen("tcp", fmt.Sprintf(":%d", port))
}

// DialTCP: Client (İzleyici) tarafı için karşıya bağlanır.
func (m *Manager) DialTCP(targetIP string, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) 
	defer cancel()

	conn, err := m.Server.Dial(ctx, "tcp", fmt.Sprintf("%s:%d", targetIP, port))
	if err != nil {
		return nil, err
	}

	// 🔥 NETWORK BOOST (AĞ HIZLANDIRMA)
	// Standart tamponu (64KB) devasa boyuta (1MB) çıkarıyoruz.
	// Bu, "Veri Şişmesi" sesini keser ve akışı pürüzsüzleştirir.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(10 * time.Second)
		
		// 1 MB Okuma/Yazma Tamponu (Standartın 16 katı)
		tcpConn.SetWriteBuffer(128 * 1024) 
		tcpConn.SetReadBuffer(128 * 1024)
	}

	return conn, nil
}