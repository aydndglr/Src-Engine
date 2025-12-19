/*

package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sync"
	"syscall"

	"src-engine/internal/audio"
	"src-engine/internal/clipboard"
	"src-engine/internal/core"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
)

// UI Durum Yönetimi
var (
	uiConnected bool
	uiConnMutex sync.Mutex
)

func main() {
	// 🛡️ Çökme koruması (Panic Catcher)
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("🔥 KRİTİK HATA (PANIC):", r)
			fmt.Println(string(debug.Stack()))
		}
	}()

	// --- 1. AYARLAR ---
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-device"
	}
	fmt.Printf("💻 Cihaz Kimliği: %s\n", hostname)

	controlURL := flag.String("url", "https://vpn.cybervpn.tr", "Headscale URL")
	authKey := flag.String("key", "", "Auth Key")
	connectIP := flag.String("connect", "", "Hedef IP (Sadece Client Modu için)")
	uiPort := flag.Int("ui-port", 9000, "UI (Electron) Portu")
	width := flag.Int("w", 0, "Genişlik (0 = Otomatik)")
	height := flag.Int("h", 0, "Yükseklik (0 = Otomatik)")
	fps := flag.Int("fps", 30, "FPS")

	flag.Parse()

	if *authKey == "" {
		log.Fatal("❌ HATA: -key parametresi zorunlu!")
	}

	// --- 2. NETWORK BAŞLAT ---
	netMgr, err := network.NewManager(hostname, *authKey, *controlURL)
	if err != nil {
		log.Fatalf("Network hatası: %v", err)
	}

	if err := netMgr.StartTunnel(); err != nil {
		log.Fatalf("Tünel hatası: %v", err)
	}

	fmt.Printf("STATUS:READY,IP:%s,HOST:%s\n", netMgr.MyIP, hostname)

	// --- 3. PANO (CLIPBOARD) YÖNETİCİSİ BAŞLAT ---
	if err := clipboard.Init(); err != nil {
		fmt.Println("⚠️ Pano sistemi başlatılamadı:", err)
	}
	clipMgr := clipboard.NewManager()
	clipMgr.StartWatcher(context.Background())

	// --- 4. SES (AUDIO) YÖNETİCİSİ - DEVRE DIŞI ---
	// Performans testi için ses modülünü şimdilik nil olarak bırakıyoruz.
	// audioMgr, err := audio.NewManager()
	// if err != nil {
	// 	fmt.Println("⚠️ Ses sistemi başlatılamadı:", err)
	// } else {
	// 	defer audioMgr.Close()
	// }
	var audioMgr *audio.Manager = nil // Ses yöneticisi bilerek boş bırakıldı

	// --- 5. MOTORU KUR ---
	engineCfg := core.Config{Width: *width, Height: *height, FPS: *fps}
	eng := core.NewEngine(netMgr, engineCfg)

	// --- 6. MODU SEÇ VE BAŞLAT ---
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	if *connectIP == "" {
		// --- HOST (YAYINCI) MODU ---

		// A) Görüntü/Input Kanalı (Port 44444)
		go func() {
			if err := eng.StartHost(44444); err != nil {
				log.Fatalf("Host hatası: %v", err)
			}
		}()

		// B) Veri Kanalı (Port 44445 - Clipboard/Dosya/Ses)
		go func() {
			l, err := netMgr.ListenTCP(44445)
			if err != nil {
				log.Printf("Veri Kanalı Hatası: %v", err)
				return
			}
			fmt.Println("📋 Veri Kanalı Hazır (Port 44445)")

			for {
				conn, err := l.Accept()
				if err != nil {
					continue
				}
				// audioMgr nil olduğu için ses işlenmeyecek ama kod hata vermez
				go handleDataSession(conn, clipMgr, audioMgr)
			}
		}()

		// C) UI Köprüsü
		go startUIServer(*uiPort, eng)

		fmt.Println("🎥 Mod: SUNUCU (Bağlantı bekleniyor...)")
		<-sigs

	} else {
		// --- CLIENT (İZLEYİCİ) MODU ---
		fmt.Printf("📺 Mod: İZLEYİCİ (Hedef: %s)\n", *connectIP)

		// Ses istemcisini başlatma kısmını da devre dışı bırakıyoruz


		go func() {
			conn, err := netMgr.DialTCP(*connectIP, 44445)
			if err != nil {
				log.Printf("⚠️ Veri kanalına bağlanılamadı: %v", err)
				return
			}
			fmt.Println("📋 Veri Kanalı Bağlandı!")
			handleDataSession(conn, clipMgr, audioMgr)
		}()

		go startUIServer(*uiPort, eng)

		go func() {
			if err := eng.StartClient(*connectIP, 44444); err != nil {
				log.Printf("Client hatası: %v", err)
				os.Exit(1)
			}
		}()
		<-sigs
	}

	fmt.Println("👋 Kapatılıyor...")
}

// --- UI SUNUCUSU ---
func startUIServer(port int, eng *core.Engine) {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("🔌 UI Köprüsü Hazır: 127.0.0.1:%d\n", port)

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		uiConnMutex.Lock()
		uiConnected = true
		uiConnMutex.Unlock()

		fmt.Println("✅ UI Bağlandı!")
		go handleUIDataTransfer(conn, eng)
	}
}

// handleDataSession: Clipboard, Dosya, Ses trafiği.
func handleDataSession(conn net.Conn, cm *clipboard.ClipboardManager, am *audio.Manager) {
	defer conn.Close()

	var currentFile *os.File
	var currentFileSize int64
	var receivedBytes int64
	audioStreaming := false

	cm.SetCallback(func(text string) {
		_ = protocol.WriteDataPacket(conn, protocol.DataTypeClipboard, []byte(text))
	})

	for {
		header, err := protocol.ReadDataHeader(conn)
		if err != nil { return }

		data := make([]byte, header.Size)
		if _, err := io.ReadFull(conn, data); err != nil { return }

		switch header.Type {
		case protocol.DataTypeClipboard:
			cm.Write(string(data))
		case protocol.DataTypeAudio:
			// am nil ise hiçbir şey yapma
			if am != nil { am.PlayPacket(data) }
		case protocol.DataTypeAudioCmd:
			cmd := string(data)
			if cmd == "START" && !audioStreaming && am != nil {
				audioStreaming = true
				go am.StartHost(func(audioData []byte) {
					if audioStreaming {
						_ = protocol.WriteDataPacket(conn, protocol.DataTypeAudio, audioData)
					}
				})
			} else if cmd == "STOP" {
				audioStreaming = false
			}
		case protocol.DataTypeFileStart:
			meta, _ := protocol.DecodeFileStart(data)
			home, _ := os.UserHomeDir()
			downloadDir := filepath.Join(home, "Downloads")
			_ = os.MkdirAll(downloadDir, 0755)
			fullPath := filepath.Join(downloadDir, filepath.Base(meta.Name))
			f, _ := os.Create(fullPath)
			currentFile = f
			currentFileSize = meta.Size
			receivedBytes = 0
		case protocol.DataTypeFileData:
			if currentFile != nil {
				n, _ := currentFile.Write(data)
				receivedBytes += int64(n)
				if receivedBytes >= currentFileSize {
					currentFile.Close()
					currentFile = nil
				}
			}
		}
	}
}

// handleUIDataTransfer: Video ve Input transferi.
func handleUIDataTransfer(uiConn net.Conn, eng *core.Engine) {
	defer func() {
		uiConn.Close()
		uiConnMutex.Lock()
		uiConnected = false
		uiConnMutex.Unlock()
	}()

	// A) Motor -> UI
	go func() {
		defer func() { recover() }()
		header := make([]byte, 4)

		for frame := range eng.FrameChan {
			binary.LittleEndian.PutUint32(header, uint32(len(frame)))
			if _, err := uiConn.Write(header); err != nil { return }
			if _, err := uiConn.Write(frame); err != nil { return }
		}
	}()

	// B) UI -> Motor
	inputBuf := make([]byte, 12)
	for {
		_, err := io.ReadFull(uiConn, inputBuf)
		if err != nil { return }

		ev := protocol.InputEvent{
			Device: protocol.InputDevice(inputBuf[0]),
			Action: protocol.InputAction(inputBuf[1]),
			Flags:  inputBuf[2],
			X:      int16(binary.LittleEndian.Uint16(inputBuf[4:6])),
			Y:      int16(binary.LittleEndian.Uint16(inputBuf[6:8])),
			Wheel:  int16(binary.LittleEndian.Uint16(inputBuf[8:10])),
			Key:    binary.LittleEndian.Uint16(inputBuf[10:12]),
		}
		eng.SendInput(ev)
	}
}
	*/






/*


package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"       // <--- RAM takibi için eklendi
	"runtime/debug"
	"sync"
	"syscall"
	"time"          // <--- Zamanlayıcı için eklendi

	"src-engine/internal/audio"
	"src-engine/internal/clipboard"
	"src-engine/internal/core"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
)

// UI Durum Yönetimi
var (
	uiConnected bool
	uiConnMutex sync.Mutex
)

// --- NABIZ VE LOGLAMA FONKSİYONU ---
// Bu fonksiyon "Kara Kutu" görevi görür. Her şeyi dosyaya kaydeder.
func startDebugLogger() {
	// Log dosyasını oluştur veya varsa sonuna ekle
	f, err := os.OpenFile("debug_log.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("⚠️ Log dosyası oluşturulamadı:", err)
		return
	}

	// Logları hem ekrana (Stdout) hem de dosyaya (f) yaz
	multiWriter := io.MultiWriter(os.Stdout, f)
	log.SetOutput(multiWriter)

	// Arka planda çalışan nabız kontrolü
	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			
			// Alloc: Şu an kullanılan RAM (MB)
			// NumGoroutine: Çalışan iş parçacığı sayısı
			log.Printf("[NABIZ] RAM: %v MB | Goroutines: %d\n", m.Alloc/1024/1024, runtime.NumGoroutine())
			
			time.Sleep(5 * time.Second)
		}
	}()
}

func main() {
	// 1. LOGLAMAYI BAŞLAT (En başta çalışmalı)
	startDebugLogger()
	log.Println("🚀 MOTOR BAŞLATILIYOR... (Debug Modu)")

	// 🛡️ Çökme koruması (Panic Catcher)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("🔥 KRİTİK HATA (PANIC): %v\n", r)
			log.Println(string(debug.Stack()))
			// Log dosyasını diske yazabilmesi için 2 saniye bekle
			time.Sleep(2 * time.Second)
		}
	}()

	// --- 1. AYARLAR ---
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-device"
	}
	log.Printf("💻 Cihaz Kimliği: %s\n", hostname)

	controlURL := flag.String("url", "https://vpn.cybervpn.tr", "Headscale URL")
	authKey := flag.String("key", "", "Auth Key")
	connectIP := flag.String("connect", "", "Hedef IP (Sadece Client Modu için)")
	uiPort := flag.Int("ui-port", 9000, "UI (Electron) Portu")
	width := flag.Int("w", 0, "Genişlik (0 = Otomatik)")
	height := flag.Int("h", 0, "Yükseklik (0 = Otomatik)")
	fps := flag.Int("fps", 30, "FPS")

	flag.Parse()

	if *authKey == "" {
		log.Fatal("❌ HATA: -key parametresi zorunlu!")
	}

	// --- 2. NETWORK BAŞLAT ---
	netMgr, err := network.NewManager(hostname, *authKey, *controlURL)
	if err != nil {
		log.Fatalf("Network hatası: %v", err)
	}

	if err := netMgr.StartTunnel(); err != nil {
		log.Fatalf("Tünel hatası: %v", err)
	}

	log.Printf("STATUS:READY,IP:%s,HOST:%s\n", netMgr.MyIP, hostname)

	// --- 3. PANO (CLIPBOARD) YÖNETİCİSİ BAŞLAT ---
	if err := clipboard.Init(); err != nil {
		log.Println("⚠️ Pano sistemi başlatılamadı:", err)
	}
	clipMgr := clipboard.NewManager()
	clipMgr.StartWatcher(context.Background())

	// --- 4. SES (AUDIO) YÖNETİCİSİ - DEVRE DIŞI ---
	// Performans testi için ses modülünü şimdilik nil olarak bırakıyoruz.
	var audioMgr *audio.Manager = nil 

	// --- 5. MOTORU KUR ---
	engineCfg := core.Config{Width: *width, Height: *height, FPS: *fps}
	eng := core.NewEngine(netMgr, engineCfg)

	// --- 6. MODU SEÇ VE BAŞLAT ---
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	if *connectIP == "" {
		// --- HOST (YAYINCI) MODU ---

		// A) Görüntü/Input Kanalı (Port 44444)
		go func() {
			if err := eng.StartHost(44444); err != nil {
				log.Fatalf("Host hatası: %v", err)
			}
		}()

		// B) Veri Kanalı (Port 44445 - Clipboard/Dosya/Ses)
		go func() {
			l, err := netMgr.ListenTCP(44445)
			if err != nil {
				log.Printf("Veri Kanalı Hatası: %v", err)
				return
			}
			log.Println("📋 Veri Kanalı Hazır (Port 44445)")

			for {
				conn, err := l.Accept()
				if err != nil {
					continue
				}
				// audioMgr nil olduğu için ses işlenmeyecek ama kod hata vermez
				go handleDataSession(conn, clipMgr, audioMgr)
			}
		}()

		// C) UI Köprüsü
		go startUIServer(*uiPort, eng)

		log.Println("🎥 Mod: SUNUCU (Bağlantı bekleniyor...)")
		<-sigs

	} else {
		// --- CLIENT (İZLEYİCİ) MODU ---
		log.Printf("📺 Mod: İZLEYİCİ (Hedef: %s)\n", *connectIP)

		go func() {
			conn, err := netMgr.DialTCP(*connectIP, 44445)
			if err != nil {
				log.Printf("⚠️ Veri kanalına bağlanılamadı: %v", err)
				return
			}
			log.Println("📋 Veri Kanalı Bağlandı!")
			handleDataSession(conn, clipMgr, audioMgr)
		}()

		go startUIServer(*uiPort, eng)

		go func() {
			if err := eng.StartClient(*connectIP, 44444); err != nil {
				log.Printf("Client hatası: %v", err)
				os.Exit(1)
			}
		}()
		<-sigs
	}

	log.Println("👋 Kapatılıyor...")
}

// --- UI SUNUCUSU ---
func startUIServer(port int, eng *core.Engine) {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("🔌 UI Köprüsü Hazır: 127.0.0.1:%d\n", port)

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		uiConnMutex.Lock()
		uiConnected = true
		uiConnMutex.Unlock()

		log.Println("✅ UI Bağlandı!")
		go handleUIDataTransfer(conn, eng)
	}
}

// handleDataSession: Clipboard, Dosya, Ses trafiği.
func handleDataSession(conn net.Conn, cm *clipboard.ClipboardManager, am *audio.Manager) {
	defer conn.Close()

	var currentFile *os.File
	var currentFileSize int64
	var receivedBytes int64
	audioStreaming := false

	cm.SetCallback(func(text string) {
		_ = protocol.WriteDataPacket(conn, protocol.DataTypeClipboard, []byte(text))
	})

	for {
		header, err := protocol.ReadDataHeader(conn)
		if err != nil { return }

		data := make([]byte, header.Size)
		if _, err := io.ReadFull(conn, data); err != nil { return }

		switch header.Type {
		case protocol.DataTypeClipboard:
			cm.Write(string(data))
		case protocol.DataTypeAudio:
			// am nil ise hiçbir şey yapma
			if am != nil { am.PlayPacket(data) }
		case protocol.DataTypeAudioCmd:
			cmd := string(data)
			if cmd == "START" && !audioStreaming && am != nil {
				audioStreaming = true
				go am.StartHost(func(audioData []byte) {
					if audioStreaming {
						_ = protocol.WriteDataPacket(conn, protocol.DataTypeAudio, audioData)
					}
				})
			} else if cmd == "STOP" {
				audioStreaming = false
			}
		case protocol.DataTypeFileStart:
			meta, _ := protocol.DecodeFileStart(data)
			home, _ := os.UserHomeDir()
			downloadDir := filepath.Join(home, "Downloads")
			_ = os.MkdirAll(downloadDir, 0755)
			fullPath := filepath.Join(downloadDir, filepath.Base(meta.Name))
			f, _ := os.Create(fullPath)
			currentFile = f
			currentFileSize = meta.Size
			receivedBytes = 0
		case protocol.DataTypeFileData:
			if currentFile != nil {
				n, _ := currentFile.Write(data)
				receivedBytes += int64(n)
				if receivedBytes >= currentFileSize {
					currentFile.Close()
					currentFile = nil
				}
			}
		}
	}
}

// handleUIDataTransfer: Video ve Input transferi.
func handleUIDataTransfer(uiConn net.Conn, eng *core.Engine) {
	defer func() {
		uiConn.Close()
		uiConnMutex.Lock()
		uiConnected = false
		uiConnMutex.Unlock()
	}()

	// A) Motor -> UI
	go func() {
		defer func() { recover() }()
		header := make([]byte, 4)

		for frame := range eng.FrameChan {
			binary.LittleEndian.PutUint32(header, uint32(len(frame)))
			if _, err := uiConn.Write(header); err != nil { return }
			if _, err := uiConn.Write(frame); err != nil { return }
		}
	}()

	// B) UI -> Motor
	inputBuf := make([]byte, 12)
	for {
		_, err := io.ReadFull(uiConn, inputBuf)
		if err != nil { return }

		ev := protocol.InputEvent{
			Device: protocol.InputDevice(inputBuf[0]),
			Action: protocol.InputAction(inputBuf[1]),
			Flags:  inputBuf[2],
			X:      int16(binary.LittleEndian.Uint16(inputBuf[4:6])),
			Y:      int16(binary.LittleEndian.Uint16(inputBuf[6:8])),
			Wheel:  int16(binary.LittleEndian.Uint16(inputBuf[8:10])),
			Key:    binary.LittleEndian.Uint16(inputBuf[10:12]),
		}
		eng.SendInput(ev)
	}
}
*/
/*

package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"src-engine/internal/audio"
	"src-engine/internal/clipboard"
	"src-engine/internal/core"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
)

// UI Durum Yönetimi
var (
	uiConnected bool
	uiConnMutex sync.Mutex
)

// --- NABIZ VE LOGLAMA FONKSİYONU ---
func startDebugLogger() {
	f, err := os.OpenFile("debug_log.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("⚠️ Log dosyası oluşturulamadı:", err)
		return
	}

	multiWriter := io.MultiWriter(os.Stdout, f)
	log.SetOutput(multiWriter)

	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			log.Printf("[NABIZ] RAM: %v MB | Goroutines: %d\n", m.Alloc/1024/1024, runtime.NumGoroutine())
			time.Sleep(5 * time.Second)
		}
	}()
}

func main() {
	startDebugLogger()
	log.Println("🚀 MOTOR BAŞLATILIYOR... (Debug Modu)")

	defer func() {
		if r := recover(); r != nil {
			log.Printf("🔥 KRİTİK HATA (PANIC): %v\n", r)
			log.Println(string(debug.Stack()))
			time.Sleep(2 * time.Second)
		}
	}()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-device"
	}
	log.Printf("💻 Cihaz Kimliği: %s\n", hostname)

	controlURL := flag.String("url", "https://vpn.cybervpn.tr", "Headscale URL")
	authKey := flag.String("key", "", "Auth Key")
	connectIP := flag.String("connect", "", "Hedef IP (Sadece Client Modu için)")
	uiPort := flag.Int("ui-port", 9000, "UI (Electron) Portu")
	width := flag.Int("w", 0, "Genişlik (0 = Otomatik)")
	height := flag.Int("h", 0, "Yükseklik (0 = Otomatik)")
	fps := flag.Int("fps", 30, "FPS")
	rawMode := flag.Bool("raw", false, "Ham video modu (VLC/FFplay testi için header göndermez)")
	flag.Parse()

	if *authKey == "" {
		log.Fatal("❌ HATA: -key parametresi zorunlu!")
	}

	// --- NETWORK ---
	netMgr, err := network.NewManager(hostname, *authKey, *controlURL)
	if err != nil {
		log.Fatalf("Network hatası: %v", err)
	}

	if err := netMgr.StartTunnel(); err != nil {
		log.Fatalf("Tünel hatası: %v", err)
	}

	log.Printf("STATUS:READY,IP:%s,HOST:%s\n", netMgr.MyIP, hostname)

	// --- CLIPBOARD ---
	if err := clipboard.Init(); err != nil {
		log.Println("⚠️ Pano sistemi başlatılamadı:", err)
	}
	clipMgr := clipboard.NewManager()
	clipMgr.StartWatcher(context.Background())

	// --- AUDIO (ŞİMDİLİK DEVRE DIŞI) ---
	var audioMgr *audio.Manager = nil

	// --- ENGINE ---
	engineCfg := core.Config{Width: *width, Height: *height, FPS: *fps}
	eng := core.NewEngine(netMgr, engineCfg)

	// --- SIGNALS ---
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	if *connectIP == "" {
		// --- HOST MODE ---
		go func() {
			if err := eng.StartHost(44444); err != nil {
				log.Fatalf("Host hatası: %v", err)
			}
		}()

		// Data channel (44445)
		go func() {
			l, err := netMgr.ListenTCP(44445)
			if err != nil {
				log.Printf("Veri Kanalı Hatası: %v", err)
				return
			}
			log.Println("📋 Veri Kanalı Hazır (Port 44445)")

			for {
				conn, err := l.Accept()
				if err != nil {
					continue
				}
				go handleDataSession(conn, clipMgr, audioMgr)
			}
		}()

		// UI bridge
		go startUIServer(*uiPort, eng)

		log.Println("🎥 Mod: SUNUCU (Bağlantı bekleniyor...)")
		<-sigs
	} else {
		// --- CLIENT MODE ---
		log.Printf("📺 Mod: İZLEYİCİ (Hedef: %s)\n", *connectIP)

		// Data channel
		go func() {
			conn, err := netMgr.DialTCP(*connectIP, 44445)
			if err != nil {
				log.Printf("⚠️ Veri kanalına bağlanılamadı: %v", err)
				return
			}
			log.Println("📋 Veri Kanalı Bağlandı!")
			handleDataSession(conn, clipMgr, audioMgr)
		}()

		go startUIServer(*uiPort, eng)

		go func() {
			if err := eng.StartClient(*connectIP, 44444); err != nil {
				log.Printf("Client hatası: %v", err)
				os.Exit(1)
			}
		}()

		<-sigs
	}

	log.Println("👋 Kapatılıyor...")
}

// --- UI SERVER ---
func startUIServer(port int, eng *core.Engine) {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("🔌 UI Köprüsü Hazır: 127.0.0.1:%d\n", port)

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		// UI tarafı local ama yine de buffer büyütelim
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetWriteBuffer(512 * 1024)
			_ = tcpConn.SetReadBuffer(512 * 1024)
			_ = tcpConn.SetNoDelay(true)
		}

		uiConnMutex.Lock()
		uiConnected = true
		uiConnMutex.Unlock()

		log.Println("✅ UI Bağlandı!")
		go handleUIDataTransfer(conn, eng)
	}
}

// --- DATA CHANNEL (Clipboard / File / Audio) ---
func handleDataSession(conn net.Conn, cm *clipboard.ClipboardManager, am *audio.Manager) {
	defer conn.Close()

	var (
		currentFile     *os.File
		currentFileSize int64
		receivedBytes   int64
		audioStreaming  = false
	)

	// Aynı conn’a birden fazla goroutine yazarsa paketler birbirine girer.
	// Bu yüzden tek bir write mutex.
	var writeMu sync.Mutex

	alive := atomic.Bool{}
	alive.Store(true)
	defer alive.Store(false)

	sendPacketSafe := func(t uint8, payload []byte) {
		if !alive.Load() {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()

		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = protocol.WriteDataPacket(conn, t, payload)
		_ = conn.SetWriteDeadline(time.Time{})
	}

	// Clipboard callback (bağlantı kapandıktan sonra yazmasın)
	cm.SetCallback(func(text string) {
		sendPacketSafe(protocol.DataTypeClipboard, []byte(text))
	})
	defer cm.SetCallback(nil)

	for {
		header, err := protocol.ReadDataHeader(conn)
		if err != nil {
			return
		}

		if header.Size < 0 || header.Size > 128*1024*1024 {
			// saçma boyut gelirse çık (koruma)
			return
		}

		data := make([]byte, header.Size)
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}

		switch header.Type {
		case protocol.DataTypeClipboard:
			cm.Write(string(data))

		case protocol.DataTypeAudio:
			if am != nil {
				am.PlayPacket(data)
			}

		case protocol.DataTypeAudioCmd:
			cmd := string(data)
			if cmd == "START" && !audioStreaming && am != nil {
				audioStreaming = true
				go am.StartHost(func(audioData []byte) {
					if audioStreaming {
						sendPacketSafe(protocol.DataTypeAudio, audioData)
					}
				})
			} else if cmd == "STOP" {
				audioStreaming = false
			}

		case protocol.DataTypeFileStart:
			meta, _ := protocol.DecodeFileStart(data)
			home, _ := os.UserHomeDir()
			downloadDir := filepath.Join(home, "Downloads")
			_ = os.MkdirAll(downloadDir, 0755)
			fullPath := filepath.Join(downloadDir, filepath.Base(meta.Name))
			f, _ := os.Create(fullPath)

			currentFile = f
			currentFileSize = meta.Size
			receivedBytes = 0

		case protocol.DataTypeFileData:
			if currentFile != nil {
				n, _ := currentFile.Write(data)
				receivedBytes += int64(n)
				if receivedBytes >= currentFileSize {
					_ = currentFile.Close()
					currentFile = nil
				}
			}
		}
	}
}

// --- UI BRIDGE (Video + Input) ---
//
// Kritik fix: UI okumazsa Write bloklanmasın => deadline + full write + frame drop.
const (
	uiWriteTimeout = 200 * time.Millisecond
	maxDrainFrames = 8 // backlog oluşursa en güncel frame'e yaklaşmak için
)

func writeFullWithDeadline(conn net.Conn, b []byte, d time.Duration) error {
	_ = conn.SetWriteDeadline(time.Now().Add(d))
	defer conn.SetWriteDeadline(time.Time{})

	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func drainToLatest(ch <-chan []byte, first []byte) []byte {
	latest := first
	for i := 0; i < maxDrainFrames; i++ {
		select {
		case f := <-ch:
			latest = f
		default:
			return latest
		}
	}
	return latest
}

func handleUIDataTransfer(uiConn net.Conn, eng *core.Engine) {
	defer func() {
		_ = uiConn.Close()
		uiConnMutex.Lock()
		uiConnected = false
		uiConnMutex.Unlock()
	}()

	// A) Motor -> UI
	go func() {
		defer func() { _ = recover() }()

		header := make([]byte, 4)

		for {
			frame, ok := <-eng.FrameChan
			if !ok {
				return
			}

			// UI yetişemiyorsa backlog birikir => en güncel frame'i seç
			frame = drainToLatest(eng.FrameChan, frame)

			binary.LittleEndian.PutUint32(header, uint32(len(frame)))

			// Header yaz
			if err := writeFullWithDeadline(uiConn, header, uiWriteTimeout); err != nil {
				// timeout/conn reset => UI koptu sayıp çık
				return
			}

			// Frame yaz
			if err := writeFullWithDeadline(uiConn, frame, uiWriteTimeout); err != nil {
				return
			}
		}
	}()

	// B) UI -> Motor (Input)
	inputBuf := make([]byte, 12)
	for {
		_, err := io.ReadFull(uiConn, inputBuf)
		if err != nil {
			return
		}

		ev := protocol.InputEvent{
			Device: protocol.InputDevice(inputBuf[0]),
			Action: protocol.InputAction(inputBuf[1]),
			Flags:  inputBuf[2],
			X:      int16(binary.LittleEndian.Uint16(inputBuf[4:6])),
			Y:      int16(binary.LittleEndian.Uint16(inputBuf[6:8])),
			Wheel:  int16(binary.LittleEndian.Uint16(inputBuf[8:10])),
			Key:    binary.LittleEndian.Uint16(inputBuf[10:12]),
		}
		eng.SendInput(ev)
	}
}
*/

package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"src-engine/internal/audio"
	"src-engine/internal/clipboard"
	"src-engine/internal/core"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
)

// UI Durum Yönetimi
var (
	uiConnected bool
	uiConnMutex sync.Mutex
)

// --- NABIZ VE LOGLAMA FONKSİYONU ---
func startDebugLogger() {
	f, err := os.OpenFile("debug_log.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("⚠️ Log dosyası oluşturulamadı:", err)
		return
	}

	multiWriter := io.MultiWriter(os.Stdout, f)
	log.SetOutput(multiWriter)

	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			log.Printf("[NABIZ] RAM: %v MB | Goroutines: %d\n", m.Alloc/1024/1024, runtime.NumGoroutine())
			time.Sleep(5 * time.Second)
		}
	}()
}

func main() {
	startDebugLogger()
	log.Println("🚀 MOTOR BAŞLATILIYOR... (Debug Modu)")

	defer func() {
		if r := recover(); r != nil {
			log.Printf("🔥 KRİTİK HATA (PANIC): %v\n", r)
			log.Println(string(debug.Stack()))
			time.Sleep(2 * time.Second)
		}
	}()

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-device"
	}
	log.Printf("💻 Cihaz Kimliği: %s\n", hostname)

	controlURL := flag.String("url", "https://vpn.cybervpn.tr", "Headscale URL")
	authKey := flag.String("key", "", "Auth Key")
	connectIP := flag.String("connect", "", "Hedef IP (Sadece Client Modu için)")
	uiPort := flag.Int("ui-port", 9000, "UI (Electron) Portu")
	width := flag.Int("w", 0, "Genişlik (0 = Otomatik)")
	height := flag.Int("h", 0, "Yükseklik (0 = Otomatik)")
	fps := flag.Int("fps", 30, "FPS")
	
	// 🔥 YENİ PARAMETRE: Raw Mode
	rawMode := flag.Bool("raw", false, "Ham video modu (VLC/FFplay testi için header göndermez)")

	flag.Parse()

	if *authKey == "" {
		log.Fatal("❌ HATA: -key parametresi zorunlu!")
	}

	// --- NETWORK ---
	netMgr, err := network.NewManager(hostname, *authKey, *controlURL)
	if err != nil {
		log.Fatalf("Network hatası: %v", err)
	}

	if err := netMgr.StartTunnel(); err != nil {
		log.Fatalf("Tünel hatası: %v", err)
	}

	log.Printf("STATUS:READY,IP:%s,HOST:%s\n", netMgr.MyIP, hostname)

	// --- CLIPBOARD ---
	if err := clipboard.Init(); err != nil {
		log.Println("⚠️ Pano sistemi başlatılamadı:", err)
	}
	clipMgr := clipboard.NewManager()
	clipMgr.StartWatcher(context.Background())

	// --- AUDIO (ŞİMDİLİK DEVRE DIŞI) ---
	var audioMgr *audio.Manager = nil

	// --- ENGINE ---
	// 🔥 RawMode ayarını Config'e ekliyoruz (Engine struct'ını da güncellemen gerekebilir)
	// Eğer Engine Config'inde RawMode yoksa, önce internal/core/engine.go'daki Config struct'ına eklemelisin.
	// Ben varsayılan olarak eklediğini varsayıyorum.
	engineCfg := core.Config{Width: *width, Height: *height, FPS: *fps, RawMode: *rawMode}
	eng := core.NewEngine(netMgr, engineCfg)

	// --- SIGNALS ---
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	if *connectIP == "" {
		// --- HOST MODE ---
		go func() {
			if err := eng.StartHost(44444); err != nil {
				log.Fatalf("Host hatası: %v", err)
			}
		}()

		// Data channel (44445)
		go func() {
			l, err := netMgr.ListenTCP(44445)
			if err != nil {
				log.Printf("Veri Kanalı Hatası: %v", err)
				return
			}
			log.Println("📋 Veri Kanalı Hazır (Port 44445)")

			for {
				conn, err := l.Accept()
				if err != nil {
					continue
				}
				go handleDataSession(conn, clipMgr, audioMgr)
			}
		}()

		// UI bridge
		go startUIServer(*uiPort, eng)

		log.Println("🎥 Mod: SUNUCU (Bağlantı bekleniyor...)")
		<-sigs
	} else {
		// --- CLIENT MODE ---
		log.Printf("📺 Mod: İZLEYİCİ (Hedef: %s)\n", *connectIP)

		// Data channel
		go func() {
			conn, err := netMgr.DialTCP(*connectIP, 44445)
			if err != nil {
				log.Printf("⚠️ Veri kanalına bağlanılamadı: %v", err)
				return
			}
			log.Println("📋 Veri Kanalı Bağlandı!")
			handleDataSession(conn, clipMgr, audioMgr)
		}()

		go startUIServer(*uiPort, eng)

		go func() {
			if err := eng.StartClient(*connectIP, 44444); err != nil {
				log.Printf("Client hatası: %v", err)
				os.Exit(1)
			}
		}()

		<-sigs
	}

	log.Println("👋 Kapatılıyor...")
}

// --- UI SERVER ---
func startUIServer(port int, eng *core.Engine) {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("🔌 UI Köprüsü Hazır: 127.0.0.1:%d (RawMode: %v)\n", port, eng.Conf.RawMode)

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		// UI tarafı local ama yine de buffer büyütelim
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetWriteBuffer(512 * 1024)
			_ = tcpConn.SetReadBuffer(512 * 1024)
			_ = tcpConn.SetNoDelay(true)
		}

		uiConnMutex.Lock()
		uiConnected = true
		uiConnMutex.Unlock()

		log.Println("✅ UI Bağlandı!")
		go handleUIDataTransfer(conn, eng)
	}
}

// --- DATA CHANNEL (Clipboard / File / Audio) ---
func handleDataSession(conn net.Conn, cm *clipboard.ClipboardManager, am *audio.Manager) {
	defer conn.Close()

	var (
		currentFile     *os.File
		currentFileSize int64
		receivedBytes   int64
		audioStreaming  = false
	)

	var writeMu sync.Mutex

	alive := atomic.Bool{}
	alive.Store(true)
	defer alive.Store(false)

	sendPacketSafe := func(t uint8, payload []byte) {
		if !alive.Load() {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()

		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = protocol.WriteDataPacket(conn, t, payload)
		_ = conn.SetWriteDeadline(time.Time{})
	}

	cm.SetCallback(func(text string) {
		sendPacketSafe(protocol.DataTypeClipboard, []byte(text))
	})
	defer cm.SetCallback(nil)

	for {
		header, err := protocol.ReadDataHeader(conn)
		if err != nil {
			return
		}

		if header.Size < 0 || header.Size > 128*1024*1024 {
			return
		}

		data := make([]byte, header.Size)
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}

		switch header.Type {
		case protocol.DataTypeClipboard:
			cm.Write(string(data))

		case protocol.DataTypeAudio:
			if am != nil {
				am.PlayPacket(data)
			}

		case protocol.DataTypeAudioCmd:
			cmd := string(data)
			if cmd == "START" && !audioStreaming && am != nil {
				audioStreaming = true
				go am.StartHost(func(audioData []byte) {
					if audioStreaming {
						sendPacketSafe(protocol.DataTypeAudio, audioData)
					}
				})
			} else if cmd == "STOP" {
				audioStreaming = false
			}

		case protocol.DataTypeFileStart:
			meta, _ := protocol.DecodeFileStart(data)
			home, _ := os.UserHomeDir()
			downloadDir := filepath.Join(home, "Downloads")
			_ = os.MkdirAll(downloadDir, 0755)
			fullPath := filepath.Join(downloadDir, filepath.Base(meta.Name))
			f, _ := os.Create(fullPath)

			currentFile = f
			currentFileSize = meta.Size
			receivedBytes = 0

		case protocol.DataTypeFileData:
			if currentFile != nil {
				n, _ := currentFile.Write(data)
				receivedBytes += int64(n)
				if receivedBytes >= currentFileSize {
					_ = currentFile.Close()
					currentFile = nil
				}
			}
		}
	}
}

// --- UI BRIDGE (Video + Input) ---
const (
	uiWriteTimeout = 200 * time.Millisecond
	maxDrainFrames = 8 
)

func writeFullWithDeadline(conn net.Conn, b []byte, d time.Duration) error {
	_ = conn.SetWriteDeadline(time.Now().Add(d))
	defer conn.SetWriteDeadline(time.Time{})

	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func drainToLatest(ch <-chan []byte, first []byte) []byte {
	latest := first
	for i := 0; i < maxDrainFrames; i++ {
		select {
		case f := <-ch:
			latest = f
		default:
			return latest
		}
	}
	return latest
}

func handleUIDataTransfer(uiConn net.Conn, eng *core.Engine) {
	defer func() {
		_ = uiConn.Close()
		uiConnMutex.Lock()
		uiConnected = false
		uiConnMutex.Unlock()
	}()

	// A) Motor -> UI
	go func() {
		defer func() { _ = recover() }()

		header := make([]byte, 4)

		for {
			frame, ok := <-eng.FrameChan
			if !ok {
				return
			}

			frame = drainToLatest(eng.FrameChan, frame)

			// 🔥 RAW MODE KONTROLÜ
			// Eğer -raw verilmediyse header gönder (Electron için)
			// Eğer -raw verildiyse SADECE FRAME gönder (FFplay/VLC için)
			if !eng.Conf.RawMode {
				binary.LittleEndian.PutUint32(header, uint32(len(frame)))
				if err := writeFullWithDeadline(uiConn, header, uiWriteTimeout); err != nil {
					return
				}
			}

			// Frame yaz
			if err := writeFullWithDeadline(uiConn, frame, uiWriteTimeout); err != nil {
				return
			}
		}
	}()

	// B) UI -> Motor (Input)
	inputBuf := make([]byte, 12)
	for {
		_, err := io.ReadFull(uiConn, inputBuf)
		if err != nil {
			return
		}

		ev := protocol.InputEvent{
			Device: protocol.InputDevice(inputBuf[0]),
			Action: protocol.InputAction(inputBuf[1]),
			Flags:  inputBuf[2],
			X:      int16(binary.LittleEndian.Uint16(inputBuf[4:6])),
			Y:      int16(binary.LittleEndian.Uint16(inputBuf[6:8])),
			Wheel:  int16(binary.LittleEndian.Uint16(inputBuf[8:10])),
			Key:    binary.LittleEndian.Uint16(inputBuf[10:12]),
		}
		eng.SendInput(ev)
	}
}