/*

package filetransfer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"src-engine-v2/internal/config"
	"sync"
	"time"
)

// Paket Tipleri
const (
	TypeFileStart = 1 // Metadata (Ad, Boyut)
	TypeFileData  = 2 // İçerik (Chunk)
)

// Start Paketi Yapısı
type FileMetadata struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type Manager struct {
	activeConn net.Conn
	mu         sync.Mutex
}

func NewManager() *Manager {
	return &Manager{}
}

// Start: 9003 portunu dinler
func (m *Manager) Start(ln net.Listener) {
	fmt.Printf("📂 Dosya Transfer Servisi Hazır (Port: %d)\n", config.PortFile)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}

		m.mu.Lock()
		if m.activeConn != nil {
			conn.Close()
			m.mu.Unlock()
			continue
		}
		m.activeConn = conn
		m.mu.Unlock()

		fmt.Println("📂 [DEBUG] Dosya Soketi Bağlandı! Veri bekleniyor...")
		m.handleConnection(conn)
	}
}

func (m *Manager) handleConnection(conn net.Conn) {
	defer func() {
		m.mu.Lock()
		if m.activeConn != nil {
			m.activeConn.Close()
			m.activeConn = nil
		}
		m.mu.Unlock()
		fmt.Println("📂 [DEBUG] Dosya Soketi Kapatıldı.")
	}()

	var currentFile *os.File
	var currentSize int64
	var received int64

	// Header tamponu: [Type:1][Size:4]
	headerBuf := make([]byte, 5)

	for {
		// Okuma zaman aşımı (Takılı kalmasın)
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// 1. Header Oku
		// fmt.Println("📂 [DEBUG] Header (5 byte) okunuyor...") 
		if _, err := io.ReadFull(conn, headerBuf); err != nil {
			if err != io.EOF {
				fmt.Println("❌ [DEBUG] Header okuma hatası:", err)
			}
			return
		}

		packetType := headerBuf[0]
		payloadSize := binary.LittleEndian.Uint32(headerBuf[1:])
		
		// fmt.Printf("📂 [DEBUG] Paket Geldi -> Tip: %d, Boyut: %d byte\n", packetType, payloadSize)

		// Güvenlik Limiti
		if payloadSize > 50*1024*1024 { // 50MB chunk limiti
			fmt.Println("⚠️ [DEBUG] Çok büyük paket, bağlantı kesiliyor.")
			return
		}

		// 2. Payload Oku
		payload := make([]byte, payloadSize)
		if payloadSize > 0 {
			if _, err := io.ReadFull(conn, payload); err != nil {
				fmt.Println("❌ [DEBUG] Payload okuma hatası:", err)
				return
			}
		}

		// 3. İşle
		switch packetType {
		case TypeFileStart:
			var meta FileMetadata
			if err := json.Unmarshal(payload, &meta); err != nil {
				fmt.Println("❌ [DEBUG] JSON hatası:", err)
				continue
			}

			fmt.Printf("📥 [DEBUG] Dosya Başlatma İsteği: %s (%d byte)\n", meta.Name, meta.Size)

			// --- GÜVENLİ KAYIT YOLU ---
			cwd, _ := os.Getwd()
			targetDir := filepath.Join(cwd, "Received_Files")
			
			// Klasörü oluştur
			if err := os.MkdirAll(targetDir, 0755); err != nil {
				fmt.Println("❌ [DEBUG] Klasör oluşturulamadı:", err)
				return
			}
			
			fullPath := filepath.Join(targetDir, filepath.Base(meta.Name))
			
			f, err := os.Create(fullPath)
			if err != nil {
				fmt.Printf("❌ [DEBUG] Dosya oluşturma hatası (%s): %v\n", fullPath, err)
				currentFile = nil
				continue
			}

			currentFile = f
			currentSize = meta.Size
			received = 0
			fmt.Printf("✅ [DEBUG] Dosya diske açıldı: %s\n", fullPath)

		case TypeFileData:
			if currentFile == nil {
				fmt.Println("⚠️ [DEBUG] Veri geldi ama dosya açık değil!")
				continue
			}

			n, err := currentFile.Write(payload)
			if err != nil {
				fmt.Println("❌ [DEBUG] Diske yazma hatası:", err)
				currentFile.Close()
				currentFile = nil
				continue
			}

			received += int64(n)
			// Yüzde hesabı yapıp spam yapmadan basabiliriz
			// fmt.Printf("Writing... %d/%d\r", received, currentSize)

			// Bitti mi?
			if received >= currentSize {
				fmt.Println("\n✨ [DEBUG] Dosya Başarıyla Tamamlandı!")
				currentFile.Close()
				currentFile = nil
				currentSize = 0
				received = 0
			}
		
		default:
			fmt.Printf("❓ [DEBUG] Bilinmeyen paket tipi: %d\n", packetType)
		}
	}
}

*/

package filetransfer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"src-engine-v2/internal/config"
	"sync"
	"time"
)

// Paket Tipleri
const (
	TypeFileStart = 1 // Metadata (Ad, Boyut)
	TypeFileData  = 2 // İçerik (Chunk)
)

// Start Paketi Yapısı
type FileMetadata struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type Manager struct {
	activeConn net.Conn
	mu         sync.Mutex
}

func NewManager() *Manager {
	return &Manager{}
}

// Start: 9003 portunu dinler
func (m *Manager) Start(ln net.Listener) {
	fmt.Printf("📂 Dosya Transfer Servisi Hazır (Port: %d)\n", config.PortFile)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}

		m.mu.Lock()
		if m.activeConn != nil {
			conn.Close()
			m.mu.Unlock()
			continue
		}
		m.activeConn = conn
		m.mu.Unlock()

		fmt.Println("📂 [Bağlandı] Dosya transferi bekleniyor...")
		m.handleConnection(conn)
	}
}

func (m *Manager) handleConnection(conn net.Conn) {
	defer func() {
		m.mu.Lock()
		if m.activeConn != nil {
			m.activeConn.Close()
			m.activeConn = nil
		}
		m.mu.Unlock()
		fmt.Println("📂 Dosya bağlantısı kapatıldı.")
	}()

	var currentFile *os.File
	var currentSize int64
	var received int64

	// Header tamponu: [Type:1][Size:4]
	headerBuf := make([]byte, 5)

	for {
		// Okuma zaman aşımı (30 sn tepki vermezse kapat)
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// 1. Header Oku
		if _, err := io.ReadFull(conn, headerBuf); err != nil {
			return
		}

		packetType := headerBuf[0]
		payloadSize := binary.LittleEndian.Uint32(headerBuf[1:])

		// Güvenlik Limiti (Örn: 50MB chunk, dosya boyutu değil, paket boyutu)
		if payloadSize > 50*1024*1024 {
			fmt.Println("⚠️ Çok büyük veri paketi, bağlantı kesiliyor.")
			return
		}

		// 2. Payload Oku
		payload := make([]byte, payloadSize)
		if payloadSize > 0 {
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
		}

		// 3. İşle
		switch packetType {
		case TypeFileStart:
			var meta FileMetadata
			if err := json.Unmarshal(payload, &meta); err != nil {
				fmt.Println("❌ Dosya metadata hatası:", err)
				continue
			}

			// --- HEDEF: İNDİRİLENLER (DOWNLOADS) KLASÖRÜ ---
			home, err := os.UserHomeDir()
			var targetDir string

			if err == nil && home != "" {
				targetDir = filepath.Join(home, "Downloads")
			} else {
				// Home bulunamazsa uygulamanın yanına "Received_Files" aç
				cwd, _ := os.Getwd()
				targetDir = filepath.Join(cwd, "Received_Files")
			}

			// Klasör yoksa oluştur
			if err := os.MkdirAll(targetDir, 0755); err != nil {
				fmt.Println("⚠️ Hedef klasör hatası, yerel klasöre geçiliyor.")
				cwd, _ := os.Getwd()
				targetDir = filepath.Join(cwd, "Received_Files")
				_ = os.MkdirAll(targetDir, 0755)
			}
			
			fullPath := filepath.Join(targetDir, filepath.Base(meta.Name))
			
			f, err := os.Create(fullPath)
			if err != nil {
				fmt.Printf("❌ Dosya oluşturulamadı (%s): %v\n", fullPath, err)
				continue
			}

			currentFile = f
			currentSize = meta.Size
			received = 0
			fmt.Printf("📥 Dosya Geliyor: %s\n   -> Konum: %s\n   -> Boyut: %d byte\n", meta.Name, fullPath, meta.Size)

		case TypeFileData:
			if currentFile == nil {
				continue
			}

			n, err := currentFile.Write(payload)
			if err != nil {
				fmt.Println("❌ Yazma hatası:", err)
				currentFile.Close()
				currentFile = nil
				continue
			}

			received += int64(n)
			
			// Bitti mi?
			if received >= currentSize {
				fmt.Println("✅ Dosya başarıyla kaydedildi.")
				currentFile.Close()
				currentFile = nil
				currentSize = 0
				received = 0
			}
		}
	}
}