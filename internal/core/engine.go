/*

İLK ÇEKİRDEK AYAR

*/

/*
package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"src-engine/internal/input"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
	"src-engine/internal/video"
)

// Config: Motorun çalışma ayarları
type Config struct {
	Width  int
	Height int
	FPS    int
}

// Engine: Sistemin beyni.
type Engine struct {
	NetMgr     *network.Manager
	InputMgr   input.Manager
	Conf       Config
	FrameChan  chan []byte
	ActiveConn net.Conn // Client modunda Input göndermek için saklıyoruz

	// YENİ: Onay Mekanizması için Callback
	RequestApproval func(string) bool
}

// NewEngine: Motoru hazırlar
func NewEngine(mgr *network.Manager, cfg Config) *Engine {
	// Input manager başlat (Hata olsa da devam et, sadece input çalışmaz)
	im, err := input.NewManager()
	if err != nil {
		fmt.Println("⚠️ Input manager hatası:", err)
	}

	return &Engine{
		NetMgr:    mgr,
		InputMgr:  im,
		Conf:      cfg,
		FrameChan: make(chan []byte, 30), // Tamponlu kanal
	}
}

// SetApprovalCallback: UI'dan onay alacak fonksiyonu tanımlar
func (e *Engine) SetApprovalCallback(cb func(string) bool) {
	e.RequestApproval = cb
}

// --- HOST MODU (Yayıncı) ---

func (e *Engine) StartHost(port int) error {
	listener, err := e.NetMgr.ListenTCP(port)
	if err != nil {
		return err
	}
	fmt.Printf("🎥 HOST MODU BAŞLADI (TCP Port: %d)\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Bağlantı kabul hatası:", err)
			continue
		}

		// İstemcinin IP adresini al (Headscale VPN IP)
		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Println("🔒 Bağlantı İsteği Geldi:", remoteIP)

		// 1. ONAY KONTROLÜ (Bekleme Odası)
		if e.RequestApproval != nil {
			fmt.Println("⏳ UI Onayı Bekleniyor...")
			approved := e.RequestApproval(remoteIP)

			if !approved {
				fmt.Println("⛔ Bağlantı REDDEDİLDİ:", remoteIP)
				_ = conn.Close()
				continue
			}
			fmt.Println("✅ Bağlantı ONAYLANDI:", remoteIP)
		} else {
			fmt.Println("⚠️ Onay mekanizması aktif değil, bağlantı kabul edildi.")
		}

		go e.handleHostConnection(conn)
	}
}

func (e *Engine) handleHostConnection(conn net.Conn) {
	defer conn.Close()

	// 1. INPUT OKUMA (Arka planda) - ✅ FRAMED (V2)
	// TCP stream'de conn.Read() ile gelen chunk'lar paket sınırı taşımaz.
	// Bu yüzden 14-byte header + textLen kadar payload şeklinde okuyoruz.
	go func() {
		// V2 header: 14 byte
		header := make([]byte, 14)

		for {
			// Header'ı tam oku
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}

			// TextLen (uint16) -> header[12:14]
			textLen := int(binary.LittleEndian.Uint16(header[12:14]))
			if textLen < 0 || textLen > 256 {
				// Bozuk paket -> bağlantıyı kes (güvenlik)
				return
			}

			payload := make([]byte, 14+textLen)
			copy(payload[:14], header)

			// Text varsa devamını oku
			if textLen > 0 {
				if _, err := io.ReadFull(conn, payload[14:]); err != nil {
					return
				}
			}

			ev, err := protocol.DecodeInputEvent(payload)
			if err != nil {
				continue
			}

			if e.InputMgr != nil {
				e.InputMgr.Apply(ev)
			}
		}
	}()

	// 2. VIDEO GÖNDERME (Ana döngü)
	capturer := video.NewCapturer(0)
	if err := capturer.Start(); err != nil {
		fmt.Println("Capture start error:", err)
		return
	}
	defer capturer.Close()

	// --- ÇÖZÜNÜRLÜK AYARLAMA (NATIVE / 1080p) ---
	realW, realH := capturer.Size()
	targetW, targetH := realW, realH

	// x264 even constraint
	if targetW%2 != 0 {
		targetW--
	}
	if targetH%2 != 0 {
		targetH--
	}

	fmt.Printf("🎥 Yayın Başlıyor: %dx%d @ %d FPS (Native)\n", targetW, targetH, e.Conf.FPS)

	encoder, err := video.NewEncoder(realW, realH, targetW, targetH, e.Conf.FPS)
	if err != nil {
		fmt.Println("Encoder start error:", err)
		return
	}
	defer encoder.Close()

	sizeBuf := make([]byte, 4)

	interval := time.Second / time.Duration(e.Conf.FPS)
	next := time.Now()

	for {
		now := time.Now()

		if now.Before(next) {
			time.Sleep(next.Sub(now))
			now = time.Now()
		}

		if now.Sub(next) > 2*interval {
			next = now
		}

		img, err := capturer.Capture()
		if err != nil {
			next = next.Add(interval)
			continue
		}

		h264Data := encoder.Encode(img)
		if len(h264Data) == 0 {
			next = next.Add(interval)
			continue
		}

		binary.LittleEndian.PutUint32(sizeBuf, uint32(len(h264Data)))

		if _, err := conn.Write(sizeBuf); err != nil {
			return
		}
		if _, err := conn.Write(h264Data); err != nil {
			return
		}

		next = next.Add(interval)
	}
}

// --- CLIENT MODU (İzleyici) ---

func (e *Engine) StartClient(targetIP string, port int) error {
	conn, err := e.NetMgr.DialTCP(targetIP, port)
	if err != nil {
		return err
	}

	e.ActiveConn = conn
	fmt.Println("📺 İZLEYİCİ MODU: Bağlantı kuruldu ->", targetIP)

	defer conn.Close()

	sizeBuf := make([]byte, 4)
	for {
		if _, err := io.ReadFull(conn, sizeBuf); err != nil {
			close(e.FrameChan)
			return err
		}
		frameSize := binary.LittleEndian.Uint32(sizeBuf)

		if frameSize == 0 || frameSize > 5*1024*1024 {
			fmt.Printf("⚠️ Hatalı paket boyutu: %d. Bağlantı kapatılıyor.\n", frameSize)
			close(e.FrameChan)
			return fmt.Errorf("invalid frame size")
		}

		frameData := make([]byte, frameSize)
		if _, err := io.ReadFull(conn, frameData); err != nil {
			close(e.FrameChan)
			return err
		}

		select {
		case e.FrameChan <- frameData:
		default:
		}
	}
}

// SendInput: Client modunda UI'dan gelen veriyi TCP tüneline yazar
func (e *Engine) SendInput(ev protocol.InputEvent) error {
	if e.ActiveConn == nil {
		return fmt.Errorf("bağlantı yok")
	}
	data, err := protocol.EncodeInputEvent(ev)
	if err != nil {
		return err
	}
	_, err = e.ActiveConn.Write(data)
	return err
}


*/

/*

YENİDEN AYARLAMALAR YAPILDI BAĞLANTI SORUNLARI GİDERİLDİ

*/

/*
package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"src-engine/internal/input"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
	"src-engine/internal/video"
)

// Config: Motorun çalışma ayarları
type Config struct {
	Width  int
	Height int
	FPS    int
}

// Engine: Sistemin beyni.
type Engine struct {
	NetMgr          *network.Manager
	InputMgr        input.Manager
	Conf            Config
	FrameChan       chan []byte
	ActiveConn      net.Conn // Client modunda Input göndermek için saklıyoruz

	// YENİ: Onay Mekanizması için Callback
	RequestApproval func(string) bool
}

// NewEngine: Motoru hazırlar
func NewEngine(mgr *network.Manager, cfg Config) *Engine {
	// Input manager başlat (Hata olsa da devam et, sadece input çalışmaz)
	im, err := input.NewManager()
	if err != nil {
		fmt.Println("⚠️ Input manager hatası:", err)
	}

	return &Engine{
		NetMgr:    mgr,
		InputMgr:  im,
		Conf:      cfg,
		FrameChan: make(chan []byte, 30), // Tamponlu kanal
	}
}

// SetApprovalCallback: UI'dan onay alacak fonksiyonu tanımlar
func (e *Engine) SetApprovalCallback(cb func(string) bool) {
	e.RequestApproval = cb
}

// --- HOST MODU (Yayıncı) ---

func (e *Engine) StartHost(port int) error {
	listener, err := e.NetMgr.ListenTCP(port)
	if err != nil {
		return err
	}
	fmt.Printf("🎥 HOST MODU BAŞLADI (TCP Port: %d)\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Bağlantı kabul hatası:", err)
			continue
		}

		// İstemcinin IP adresini al (Headscale VPN IP)
		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Println("🔒 Bağlantı İsteği Geldi:", remoteIP)

		// 1. ONAY KONTROLÜ (Bekleme Odası)
		if e.RequestApproval != nil {
			fmt.Println("⏳ UI Onayı Bekleniyor...")
			approved := e.RequestApproval(remoteIP)

			if !approved {
				fmt.Println("⛔ Bağlantı REDDEDİLDİ:", remoteIP)
				_ = conn.Close()
				continue
			}
			fmt.Println("✅ Bağlantı ONAYLANDI:", remoteIP)
		} else {
			fmt.Println("⚠️ Onay mekanizması aktif değil, bağlantı kabul edildi.")
		}

		go e.handleHostConnection(conn)
	}
}

func (e *Engine) handleHostConnection(conn net.Conn) {
	defer conn.Close()

	// 1. INPUT OKUMA (Arka planda) - ✅ FRAMED (V2)
	go func() {
		// V2 header: 14 byte
		header := make([]byte, 14)

		for {
			// Header'ı tam oku
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}

			// TextLen (uint16) -> header[12:14]
			textLen := int(binary.LittleEndian.Uint16(header[12:14]))
			if textLen < 0 || textLen > 256 {
				// Bozuk paket -> bağlantıyı kes (güvenlik)
				return
			}

			payload := make([]byte, 14+textLen)
			copy(payload[:14], header)

			// Text varsa devamını oku
			if textLen > 0 {
				if _, err := io.ReadFull(conn, payload[14:]); err != nil {
					return
				}
			}

			ev, err := protocol.DecodeInputEvent(payload)
			if err != nil {
				continue
			}

			if e.InputMgr != nil {
				e.InputMgr.Apply(ev)
			}
		}
	}()

	// 2. VIDEO GÖNDERME (Ana döngü)
	capturer := video.NewCapturer(0)
	if err := capturer.Start(); err != nil {
		fmt.Println("Capture start error:", err)
		return
	}
	defer capturer.Close()

	// --- ÇÖZÜNÜRLÜK AYARLAMA (NATIVE / 1080p) ---
	realW, realH := capturer.Size()
	targetW, targetH := realW, realH

	// x264 even constraint
	if targetW%2 != 0 {
		targetW--
	}
	if targetH%2 != 0 {
		targetH--
	}

	fmt.Printf("🎥 Yayın Başlıyor: %dx%d @ %d FPS (Native)\n", targetW, targetH, e.Conf.FPS)

	encoder, err := video.NewEncoder(realW, realH, targetW, targetH, e.Conf.FPS)
	if err != nil {
		fmt.Println("Encoder start error:", err)
		return
	}
	defer encoder.Close()

	// --- 🔥 TRAFİK POLİSİ BAŞLANGIÇ ---
	
	// A) Gönderim Kanalı (Otopark - 5 kare kapasiteli)
	sendChan := make(chan []byte, 5)

	// B) Gönderici Goroutine (Ağı Besleyen İşçi)
	// Encoder'dan bağımsız çalışır, ağ yavaşsa sadece otoparkı boşaltamaz.
	go func() {
		sizeBuf := make([]byte, 4)
		for data := range sendChan {
			// Yazma zaman aşımı (5 saniye ağ yanıt vermezse kopar)
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

			binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))

			if _, err := conn.Write(sizeBuf); err != nil {
				return // Bağlantı koptu, çık
			}
			if _, err := conn.Write(data); err != nil {
				return // Bağlantı koptu, çık
			}
		}
	}()
	// --- 🔥 TRAFİK POLİSİ BİTİŞ ---

	interval := time.Second / time.Duration(e.Conf.FPS)
	next := time.Now()

	for {
		now := time.Now()

		if now.Before(next) {
			time.Sleep(next.Sub(now))
			now = time.Now()
		}

		if now.Sub(next) > 2*interval {
			next = now
		}

		img, err := capturer.Capture()
		if err != nil {
			next = next.Add(interval)
			continue
		}

		h264Data := encoder.Encode(img)
		if len(h264Data) == 0 {
			next = next.Add(interval)
			continue
		}

		// --- 🔥 NON-BLOCKING GÖNDERİM ---
		// Otopark dolu mu? Doluysa bekleme, kareyi çöpe at.
		select {
		case sendChan <- h264Data:
			// Başarıyla otoparka (buffer) koyuldu
		default:
			// Kanal dolu! Ağ yavaş. Kareyi atla (Drop Frame).
			// Bu sayede RAM şişmez ve motor donmaz.
			// fmt.Print(".") // İstersen drop olduğunu görmek için açabilirsin
		}

		next = next.Add(interval)
	}
}

// --- CLIENT MODU (İzleyici) ---

func (e *Engine) StartClient(targetIP string, port int) error {
	conn, err := e.NetMgr.DialTCP(targetIP, port)
	if err != nil {
		return err
	}

	e.ActiveConn = conn
	fmt.Println("📺 İZLEYİCİ MODU: Bağlantı kuruldu ->", targetIP)

	defer conn.Close()

	sizeBuf := make([]byte, 4)
	for {
		if _, err := io.ReadFull(conn, sizeBuf); err != nil {
			close(e.FrameChan)
			return err
		}
		frameSize := binary.LittleEndian.Uint32(sizeBuf)

		if frameSize == 0 || frameSize > 5*1024*1024 {
			fmt.Printf("⚠️ Hatalı paket boyutu: %d. Bağlantı kapatılıyor.\n", frameSize)
			close(e.FrameChan)
			return fmt.Errorf("invalid frame size")
		}

		frameData := make([]byte, frameSize)
		if _, err := io.ReadFull(conn, frameData); err != nil {
			close(e.FrameChan)
			return err
		}

		select {
		case e.FrameChan <- frameData:
		default:
		}
	}
}

// SendInput: Client modunda UI'dan gelen veriyi TCP tüneline yazar
func (e *Engine) SendInput(ev protocol.InputEvent) error {
	if e.ActiveConn == nil {
		return fmt.Errorf("bağlantı yok")
	}
	data, err := protocol.EncodeInputEvent(ev)
	if err != nil {
		return err
	}
	_, err = e.ActiveConn.Write(data)
	return err
}
*/

/*

HATA VE AĞ DÜŞMELERİNE KARŞI DAHA SIKI AYARLAMALAR YAPILDI

*/

/*
package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"src-engine/internal/input"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
	"src-engine/internal/video"
)

// Config: Motorun çalışma ayarları
type Config struct {
	Width  int
	Height int
	FPS    int
}

// Engine: Sistemin beyni.
type Engine struct {
	NetMgr          *network.Manager
	InputMgr        input.Manager
	Conf            Config
	FrameChan       chan []byte
	ActiveConn      net.Conn
	RequestApproval func(string) bool
}

func NewEngine(mgr *network.Manager, cfg Config) *Engine {
	im, err := input.NewManager()
	if err != nil {
		fmt.Println("⚠️ Input manager hatası:", err)
	}

	return &Engine{
		NetMgr:    mgr,
		InputMgr:  im,
		Conf:      cfg,
		FrameChan: make(chan []byte, 30),
	}
}

func (e *Engine) SetApprovalCallback(cb func(string) bool) {
	e.RequestApproval = cb
}

// --- HOST MODU (Yayıncı) ---

func (e *Engine) StartHost(port int) error {
	listener, err := e.NetMgr.ListenTCP(port)
	if err != nil {
		return err
	}
	fmt.Printf("🎥 HOST MODU BAŞLADI (TCP Port: %d)\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Bağlantı kabul hatası:", err)
			continue
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Println("🔒 Bağlantı İsteği Geldi:", remoteIP)

		// Onay mekanizması devre dışı (Hızlı test için)
		go e.handleHostConnection(conn)
	}
}

func (e *Engine) handleHostConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("✅ Yayın Akışı Başlatıldı!")

	// 1. INPUT OKUMA (Arka planda)
	go func() {
		header := make([]byte, 14)
		for {
			if _, err := io.ReadFull(conn, header); err != nil {
				return // Bağlantı koptu
			}
			textLen := int(binary.LittleEndian.Uint16(header[12:14]))
			if textLen < 0 || textLen > 256 { return }

			payload := make([]byte, 14+textLen)
			copy(payload[:14], header)
			if textLen > 0 {
				if _, err := io.ReadFull(conn, payload[14:]); err != nil { return }
			}

			ev, err := protocol.DecodeInputEvent(payload)
			if err == nil && e.InputMgr != nil {
				e.InputMgr.Apply(ev)
			}
		}
	}()

	// 2. VIDEO GÖNDERME
	capturer := video.NewCapturer(0)
	if err := capturer.Start(); err != nil {
		fmt.Println("Capture start error:", err)
		return
	}
	defer capturer.Close()

	realW, realH := capturer.Size()
	targetW, targetH := realW, realH
	if targetW%2 != 0 { targetW-- }
	if targetH%2 != 0 { targetH-- }

	encoder, err := video.NewEncoder(realW, realH, targetW, targetH, e.Conf.FPS)
	if err != nil {
		fmt.Println("Encoder start error:", err)
		return
	}
	defer encoder.Close()

	// --- 🚀 SENKRONİZASYON MEKANİZMASI ---
	sendChan := make(chan []byte, 5) // Otopark
	killSwitch := make(chan bool)    // Acil Durdurma Butonu

	// A) GÖNDERİCİ (WRITER)
	go func() {
		defer close(killSwitch) // Ölürsem herkese haber ver
		sizeBuf := make([]byte, 4)
		
		for data := range sendChan {
			// 5 saniye içinde yazamazsam bağlantı ölü demektir
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

			binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))
			if _, err := conn.Write(sizeBuf); err != nil {
				fmt.Println("❌ Ağ Yazma Hatası (Header):", err)
				return
			}
			if _, err := conn.Write(data); err != nil {
				fmt.Println("❌ Ağ Yazma Hatası (Body):", err)
				return
			}
		}
	}()

	// B) YAKALAYICI (CAPTURER LOOP)
	interval := time.Second / time.Duration(e.Conf.FPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-killSwitch:
			// Writer öldü, ben de intihar ediyorum.
			fmt.Println("🛑 Ağ koptuğu için yayın durduruluyor.")
			return
		case <-ticker.C:
			// Rutin yakalama işlemi
		}

		img, err := capturer.Capture()
		if err != nil { continue }

		h264Data := encoder.Encode(img)
		if len(h264Data) == 0 { continue }

		// Otoparka koymaya çalış
		select {
		case sendChan <- h264Data:
			// Başarılı
		case <-killSwitch:
			return // Writer ölmüş, boşa kürek çekme
		default:
			// Ağ yavaş, paket atla (Drop Frame)
			// Ama bağlantıyı koparma, belki düzelir.
		}
	}
}

// --- CLIENT MODU (İzleyici) ---

func (e *Engine) StartClient(targetIP string, port int) error {
	// TCP Timeout süresini kısalttık (10sn)
	conn, err := e.NetMgr.DialTCP(targetIP, port)
	if err != nil {
		return err
	}

	e.ActiveConn = conn
	fmt.Println("📺 İZLEYİCİ MODU: Bağlantı kuruldu ->", targetIP)

	defer conn.Close()

	// Client tarafında da OKUMA Timeout'u olmalı
	// Eğer 5 saniye veri gelmezse bağlantıyı kopar ki yeniden bağlanabilsin
	sizeBuf := make([]byte, 4)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		
		if _, err := io.ReadFull(conn, sizeBuf); err != nil {
			fmt.Println("⚠️ Okuma Hatası/Zaman Aşımı:", err)
			close(e.FrameChan)
			return err
		}
		
		frameSize := binary.LittleEndian.Uint32(sizeBuf)
		if frameSize == 0 || frameSize > 5*1024*1024 {
			close(e.FrameChan)
			return fmt.Errorf("invalid frame size")
		}

		frameData := make([]byte, frameSize)
		if _, err := io.ReadFull(conn, frameData); err != nil {
			close(e.FrameChan)
			return err
		}

		select {
		case e.FrameChan <- frameData:
		default:
		}
	}
}

// SendInput: Client modunda UI'dan gelen veriyi TCP tüneline yazar
func (e *Engine) SendInput(ev protocol.InputEvent) error {
	if e.ActiveConn == nil {
		return fmt.Errorf("bağlantı yok")
	}
	data, err := protocol.EncodeInputEvent(ev)
	if err != nil {
		return err
	}
	// Input gönderirken de timeout koyalım
	e.ActiveConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, err = e.ActiveConn.Write(data)
	return err
}
*/
/*

1080P'DE AGRESİF SIKIŞTIRMA YAPILDI

*/
/*
package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"src-engine/internal/input"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
	"src-engine/internal/video"
)

// Config: Motorun çalışma ayarları
type Config struct {
	Width  int
	Height int
	FPS    int
}

// Engine: Sistemin beyni.
type Engine struct {
	NetMgr          *network.Manager
	InputMgr        input.Manager
	Conf            Config
	FrameChan       chan []byte
	ActiveConn      net.Conn
	RequestApproval func(string) bool
}

func NewEngine(mgr *network.Manager, cfg Config) *Engine {
	im, err := input.NewManager()
	if err != nil {
		fmt.Println("⚠️ Input manager hatası:", err)
	}

	return &Engine{
		NetMgr:    mgr,
		InputMgr:  im,
		Conf:      cfg,
		FrameChan: make(chan []byte, 30),
	}
}

func (e *Engine) SetApprovalCallback(cb func(string) bool) {
	e.RequestApproval = cb
}

// --- HOST MODU (Yayıncı) ---

func (e *Engine) StartHost(port int) error {
	listener, err := e.NetMgr.ListenTCP(port)
	if err != nil {
		return err
	}
	fmt.Printf("🎥 HOST MODU BAŞLADI (TCP Port: %d)\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Bağlantı kabul hatası:", err)
			continue
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Println("🔒 Bağlantı İsteği Geldi:", remoteIP)

		go e.handleHostConnection(conn)
	}
}

func (e *Engine) handleHostConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("✅ Yayın Akışı Başlatıldı!")

	// 1. INPUT OKUMA (Arka planda)
	go func() {
		header := make([]byte, 14)
		for {
			// Input okuma hatası olursa döngüden çık ama ana bağlantıyı hemen koparma
			if _, err := io.ReadFull(conn, header); err != nil {
				return 
			}
			textLen := int(binary.LittleEndian.Uint16(header[12:14]))
			if textLen < 0 || textLen > 256 { return }

			payload := make([]byte, 14+textLen)
			copy(payload[:14], header)
			if textLen > 0 {
				if _, err := io.ReadFull(conn, payload[14:]); err != nil { return }
			}

			ev, err := protocol.DecodeInputEvent(payload)
			if err == nil && e.InputMgr != nil {
				e.InputMgr.Apply(ev)
			}
		}
	}()

	// 2. VIDEO GÖNDERME
	capturer := video.NewCapturer(0)
	if err := capturer.Start(); err != nil {
		fmt.Println("Capture start error:", err)
		return
	}
	defer capturer.Close()

	realW, realH := capturer.Size()
	targetW, targetH := realW, realH
    
    // 1080p devam ediyoruz, ama çift sayı kuralına uyuyoruz
	if targetW%2 != 0 { targetW-- }
	if targetH%2 != 0 { targetH-- }

	encoder, err := video.NewEncoder(realW, realH, targetW, targetH, e.Conf.FPS)
	if err != nil {
		fmt.Println("Encoder start error:", err)
		return
	}
	defer encoder.Close()

	// --- 🛡️ RESILIENT WRITER (İNATÇI YAZICI) ---
	sendChan := make(chan []byte, 5) 
	killSwitch := make(chan bool)    

	// A) GÖNDERİCİ (WRITER) - Hata olsa da pes etmeyen yapı
	go func() {
		defer close(killSwitch)
		sizeBuf := make([]byte, 4)
		consecutiveErrors := 0 // Üst üste hata sayacı

		for data := range sendChan {
			// Deadline'ı biraz daha esnek yapıyoruz (8 saniye)
			conn.SetWriteDeadline(time.Now().Add(8 * time.Second))

			binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))
			
			// 1. Header Yazmayı Dene
			if _, err := conn.Write(sizeBuf); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (Header) %d/10: %v\n", consecutiveErrors, err)
				
				if consecutiveErrors >= 10 {
					fmt.Println("❌ Bağlantı kurtarılamadı (10x Hata), kapatılıyor.")
					return // 10 kere üst üste hata verirse anca o zaman kapat
				}
				continue // Hata verdi ama PES ETME, bir sonraki kareyi dene!
			}

			// 2. Data Yazmayı Dene
			if _, err := conn.Write(data); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (Data) %d/10: %v\n", consecutiveErrors, err)
				
				if consecutiveErrors >= 10 { return }
				continue 
			}

			// Başarılı gönderim olursa hata sayacını sıfırla
			consecutiveErrors = 0
		}
	}()

	// B) YAKALAYICI (CAPTURER LOOP)
	interval := time.Second / time.Duration(e.Conf.FPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-killSwitch:
			fmt.Println("🛑 Yayın durduruldu (Writer Kapandı).")
			return
		case <-ticker.C:
		}

		img, err := capturer.Capture()
		if err != nil { continue }

		h264Data := encoder.Encode(img)
		if len(h264Data) == 0 { continue }

		select {
		case sendChan <- h264Data:
            // Otoparka koyduk
		case <-killSwitch:
			return 
		default:
			// Otopark dolu, bu kareyi atla (Drop Frame).
            // Bağlantıyı koparma, sadece bu kareyi feda et.
		}
	}
}

// --- CLIENT MODU (İzleyici) ---

func (e *Engine) StartClient(targetIP string, port int) error {
    // Hatalı satır silindi: e.NetMgr.SetDialTimeout(...)
    // DialTCP içinde zaten context timeout var.
	
	conn, err := e.NetMgr.DialTCP(targetIP, port)
	if err != nil {
		return err
	}

	e.ActiveConn = conn
	fmt.Println("📺 İZLEYİCİ MODU: Bağlantı kuruldu ->", targetIP)

	defer conn.Close()

	sizeBuf := make([]byte, 4)
	for {
		// Client okuma timeout'u da esnek olsun (10 saniye veri gelmezse kapat)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		
		if _, err := io.ReadFull(conn, sizeBuf); err != nil {
			fmt.Println("⚠️ Okuma Hatası:", err)
			close(e.FrameChan)
			return err
		}
		
		frameSize := binary.LittleEndian.Uint32(sizeBuf)
		if frameSize == 0 || frameSize > 10*1024*1024 { // Limit 10MB'a çıkarıldı
			close(e.FrameChan)
			return fmt.Errorf("invalid frame size")
		}

		frameData := make([]byte, frameSize)
		if _, err := io.ReadFull(conn, frameData); err != nil {
			close(e.FrameChan)
			return err
		}

		select {
		case e.FrameChan <- frameData:
		default:
            // UI Thread yavaşsa kareyi atla, birikme yapma
		}
	}
}

func (e *Engine) SendInput(ev protocol.InputEvent) error {
	if e.ActiveConn == nil {
		return fmt.Errorf("bağlantı yok")
	}
	data, err := protocol.EncodeInputEvent(ev)
	if err != nil {
		return err
	}
	// Input gönderirken 2 saniye tolerans
	e.ActiveConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = e.ActiveConn.Write(data)
	return err
}

*/


/*

İLERİ AĞRESİF SIKIŞTIRMA

*/

/*
package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"src-engine/internal/input"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
	"src-engine/internal/video"
)

// Config: Motorun çalışma ayarları
type Config struct {
	Width  int
	Height int
	FPS    int
}

// Engine: Sistemin beyni.
type Engine struct {
	NetMgr          *network.Manager
	InputMgr        input.Manager
	Conf            Config
	FrameChan       chan []byte
	ActiveConn      net.Conn
	RequestApproval func(string) bool
}

func NewEngine(mgr *network.Manager, cfg Config) *Engine {
	im, err := input.NewManager()
	if err != nil {
		fmt.Println("⚠️ Input manager hatası:", err)
	}

	return &Engine{
		NetMgr:    mgr,
		InputMgr:  im,
		Conf:      cfg,
		FrameChan: make(chan []byte, 30),
	}
}

func (e *Engine) SetApprovalCallback(cb func(string) bool) {
	e.RequestApproval = cb
}

// --- HOST MODU (Yayıncı) ---

func (e *Engine) StartHost(port int) error {
	listener, err := e.NetMgr.ListenTCP(port)
	if err != nil {
		return err
	}
	fmt.Printf("🎥 HOST MODU BAŞLADI (TCP Port: %d)\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Bağlantı kabul hatası:", err)
			continue
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Println("🔒 Bağlantı İsteği Geldi:", remoteIP)

		go e.handleHostConnection(conn)
	}
}

func (e *Engine) handleHostConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("✅ Yayın Akışı Başlatıldı!")

	// 1. INPUT OKUMA (Arka planda)
	go func() {
		header := make([]byte, 14)
		for {
			if _, err := io.ReadFull(conn, header); err != nil {
				return 
			}
			textLen := int(binary.LittleEndian.Uint16(header[12:14]))
			if textLen < 0 || textLen > 256 { return }

			payload := make([]byte, 14+textLen)
			copy(payload[:14], header)
			if textLen > 0 {
				if _, err := io.ReadFull(conn, payload[14:]); err != nil { return }
			}

			ev, err := protocol.DecodeInputEvent(payload)
			if err == nil && e.InputMgr != nil {
				e.InputMgr.Apply(ev)
			}
		}
	}()

	// 2. VIDEO GÖNDERME
	capturer := video.NewCapturer(0)
	if err := capturer.Start(); err != nil {
		fmt.Println("Capture start error:", err)
		return
	}
	defer capturer.Close()

	realW, realH := capturer.Size()
	targetW, targetH := realW, realH
	if targetW%2 != 0 { targetW-- }
	if targetH%2 != 0 { targetH-- }

    // 🔥 GÜNCELLEME: 25 FPS (Tatlı Nokta)
	// Config'den gelen FPS ne olursa olsun 25'e sabitliyoruz.
	e.Conf.FPS = 25 

	fmt.Printf("🎥 Yayın Ayarı: %dx%d (Native 1080p) @ %d FPS\n", realW, realH, e.Conf.FPS)

	encoder, err := video.NewEncoder(realW, realH, targetW, targetH, e.Conf.FPS)
	if err != nil {
		fmt.Println("Encoder start error:", err)
		return
	}
	defer encoder.Close()

	// --- 🛡️ SENKRONİZASYON ---
	sendChan := make(chan []byte, 5) 
	killSwitch := make(chan bool)    

	// A) GÖNDERİCİ (WRITER)
	go func() {
		defer close(killSwitch)
		sizeBuf := make([]byte, 4)
		consecutiveErrors := 0 

		for data := range sendChan {
			// Deadline: 5 saniye
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

			binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))
			
			if _, err := conn.Write(sizeBuf); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (%d/5): %v\n", consecutiveErrors, err)
				if consecutiveErrors >= 5 { return }
				continue 
			}

			if _, err := conn.Write(data); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (%d/5): %v\n", consecutiveErrors, err)
				if consecutiveErrors >= 5 { return }
				continue 
			}
			consecutiveErrors = 0
		}
	}()

	// B) YAKALAYICI (CAPTURER LOOP)
	interval := time.Second / time.Duration(e.Conf.FPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-killSwitch:
			fmt.Println("🛑 Yayın durduruldu (Bağlantı koptu).")
			return
		case <-ticker.C:
		}

		img, err := capturer.Capture()
		if err != nil { continue }

		h264Data := encoder.Encode(img)
		if len(h264Data) == 0 { continue }

		select {
		case sendChan <- h264Data:
		case <-killSwitch:
			return 
		default:
            // Buffer doluysa atla
		}
	}
}

// --- CLIENT MODU (İzleyici) ---

func (e *Engine) StartClient(targetIP string, port int) error {
	conn, err := e.NetMgr.DialTCP(targetIP, port)
	if err != nil {
		return err
	}

	e.ActiveConn = conn
	fmt.Println("📺 İZLEYİCİ MODU: Bağlantı kuruldu ->", targetIP)

	defer conn.Close()

	sizeBuf := make([]byte, 4)
	for {
		// 10 saniye okuma timeout'u
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		
		if _, err := io.ReadFull(conn, sizeBuf); err != nil {
			fmt.Println("⚠️ Veri akışı kesildi:", err)
			close(e.FrameChan)
			return err
		}
		
		frameSize := binary.LittleEndian.Uint32(sizeBuf)
		if frameSize == 0 || frameSize > 10*1024*1024 { 
			close(e.FrameChan)
			return fmt.Errorf("invalid frame size")
		}

		frameData := make([]byte, frameSize)
		if _, err := io.ReadFull(conn, frameData); err != nil {
			close(e.FrameChan)
			return err
		}

		select {
		case e.FrameChan <- frameData:
		default:
		}
	}
}

func (e *Engine) SendInput(ev protocol.InputEvent) error {
	if e.ActiveConn == nil {
		return fmt.Errorf("bağlantı yok")
	}
	data, err := protocol.EncodeInputEvent(ev)
	if err != nil {
		return err
	}
	e.ActiveConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = e.ActiveConn.Write(data)
	return err
}
*/

/*  BELLEK ŞİŞMESİ VE PÜRÜZLÜ GÖRÜNTÜ SORUNU GİDERİLECEK       */

/*
package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"src-engine/internal/input"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
	"src-engine/internal/video"
)

// Config: Motorun çalışma ayarları
type Config struct {
	Width  int
	Height int
	FPS    int
}

// Engine: Sistemin beyni.
type Engine struct {
	NetMgr          *network.Manager
	InputMgr        input.Manager
	Conf            Config
	FrameChan       chan []byte
	ActiveConn      net.Conn
	RequestApproval func(string) bool
}

func NewEngine(mgr *network.Manager, cfg Config) *Engine {
	im, err := input.NewManager()
	if err != nil {
		fmt.Println("⚠️ Input manager hatası:", err)
	}

	return &Engine{
		NetMgr:    mgr,
		InputMgr:  im,
		Conf:      cfg,
		FrameChan: make(chan []byte, 30),
	}
}

func (e *Engine) SetApprovalCallback(cb func(string) bool) {
	e.RequestApproval = cb
}

// --- HOST MODU (Yayıncı) ---

func (e *Engine) StartHost(port int) error {
	listener, err := e.NetMgr.ListenTCP(port)
	if err != nil {
		return err
	}
	fmt.Printf("🎥 HOST MODU BAŞLADI (TCP Port: %d)\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Bağlantı kabul hatası:", err)
			continue
		}

		// 🔥 HOST BOOST: Gelen bağlantının tamponlarını genişlet
		// Bunu yapmazsak Client hızlı olsa bile Host veriyi yavaş iter.
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetWriteBuffer(128 * 1024) //  Gönderim Tamponu
			tcpConn.SetReadBuffer(128 * 1024)  //  Alım Tamponu
			tcpConn.SetNoDelay(true)            // Nagle algoritmasını kapat (Anlık iletim)
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Println("🔒 Bağlantı İsteği Geldi:", remoteIP)

		go e.handleHostConnection(conn)
	}
}



func (e *Engine) handleHostConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("✅ Yayın Akışı Başlatıldı!")

	// 1. INPUT OKUMA (Eski yöntem - Geri uyumluluk için kalsın)
	// Not: Asıl input artık StartDataChannel (44445) üzerinden akıyor.
	go func() {
		header := make([]byte, 14)
		for {
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}
			textLen := int(binary.LittleEndian.Uint16(header[12:14]))
			if textLen < 0 || textLen > 256 {
				return
			}

			payload := make([]byte, 14+textLen)
			copy(payload[:14], header)
			if textLen > 0 {
				if _, err := io.ReadFull(conn, payload[14:]); err != nil {
					return
				}
			}

			ev, err := protocol.DecodeInputEvent(payload)
			if err == nil && e.InputMgr != nil {
				e.InputMgr.Apply(ev)
			}
		}
	}()

	// 2. VIDEO GÖNDERME HAZIRLIĞI
	capturer := video.NewCapturer(0)
	if err := capturer.Start(); err != nil {
		fmt.Println("Capture start error:", err)
		return
	}
	defer capturer.Close()

	realW, realH := capturer.Size()
	targetW, targetH := realW, realH
	if targetW%2 != 0 { targetW-- }
	if targetH%2 != 0 { targetH-- }

	// FPS'i 25'e sabitliyoruz (Altın Oran)
	e.Conf.FPS = 25

	fmt.Printf("🎥 Yayın Ayarı: %dx%d (Native 1080p) @ %d FPS\n", realW, realH, e.Conf.FPS)

	encoder, err := video.NewEncoder(realW, realH, targetW, targetH, e.Conf.FPS)
	if err != nil {
		fmt.Println("Encoder start error:", err)
		return
	}
	defer encoder.Close()

	// --- 🛡️ SENKRONİZASYON & TRAFİK KONTROLÜ ---
	sendChan := make(chan []byte, 5) // Otopark (Küçük tutuyoruz ki şişmesin)
	killSwitch := make(chan bool)

	// A) GÖNDERİCİ (WRITER) - İnatçı Mod
	go func() {
		defer close(killSwitch)
		sizeBuf := make([]byte, 4)
		consecutiveErrors := 0

		for data := range sendChan {
			// Mobil ağlar için timeout'u 5 saniye tutuyoruz (Hızlı tepki)
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

			binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))

			// 1. Header Yaz
			if _, err := conn.Write(sizeBuf); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (%d/5): %v\n", consecutiveErrors, err)
				if consecutiveErrors >= 5 {
					return // 5 kere üst üste hata verirse pes et
				}
				continue // Pes etme, sıradaki paketi dene
			}

			// 2. Data Yaz
			if _, err := conn.Write(data); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (%d/5): %v\n", consecutiveErrors, err)
				if consecutiveErrors >= 5 {
					return
				}
				continue
			}
			// Başarılı gönderimde sayacı sıfırla
			consecutiveErrors = 0
		}
	}()

	// B) YAKALAYICI (CAPTURER LOOP) - Akıllı Trafik Polisi
	interval := time.Second / time.Duration(e.Conf.FPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Adaptive Bitrate Değişkenleri
	currentBitrate := 2000 // Başlangıç: HD
	lastAdjustment := time.Now()

	for {
		select {
		case <-killSwitch:
			fmt.Println("🛑 Yayın durduruldu (Writer Kapandı).")
			return
		case <-ticker.C:
		}

		// --- 🧠 TRAFİK POLİSİ (ADAPTIVE BITRATE) ---
		// Otopark (sendChan) doluluğuna bakarak karar veriyoruz.
		queueSize := len(sendChan)

		// 3 saniyede bir ayar kontrolü yap (Sürekli değiştirip titretme)
		if time.Since(lastAdjustment) > 3*time.Second {
			if queueSize >= 3 {
				// 🚨 SIKIŞIKLIK VAR! (Mobil/Yavaş Ağ)
				// Bitrate yüksekse hemen düşür.
				if currentBitrate > 800 {
					currentBitrate = 800 // Mobil Modu (Düşük Kalite ama AKICI)
					encoder.SetBitrate(currentBitrate)
					fmt.Println("📉 Ağ tıkandı, kalite düşürülüyor: 800 kbps")
				}
			} else if queueSize == 0 {
				// 🟢 YOL AÇIK! (Wifi/Fiber)
				// Bitrate düşükse yükselt.
				if currentBitrate < 2500 {
					currentBitrate = 2500 // HD Modu
					encoder.SetBitrate(currentBitrate)
					fmt.Println("📈 Ağ rahatladı, kalite artırılıyor: 2500 kbps")
				}
			}
			lastAdjustment = time.Now()
		}

		img, err := capturer.Capture()
		if err != nil {
			continue
		}

		h264Data := encoder.Encode(img)
		if len(h264Data) == 0 {
			continue
		}

		select {
		case sendChan <- h264Data:
			// Otoparka koyduk, sorun yok.
		case <-killSwitch:
			return
		default:
			// 🗑️ DROP FRAME (Kare Düşürme)
			// Otopark tamamen doluysa bu kareyi çöpe at.
			// Bu, gecikmenin (latency) artmasını engeller.
			// İzleyici kare atlaması görür ama "DONMA" görmez.
		}
	}
}

// --- CLIENT MODU (İzleyici) ---

func (e *Engine) StartClient(targetIP string, port int) error {
	conn, err := e.NetMgr.DialTCP(targetIP, port)
	if err != nil {
		return err
	}

	e.ActiveConn = conn
	fmt.Println("📺 İZLEYİCİ MODU: Bağlantı kuruldu ->", targetIP)

	defer conn.Close()

	sizeBuf := make([]byte, 4)
	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		
		if _, err := io.ReadFull(conn, sizeBuf); err != nil {
			fmt.Println("⚠️ Veri akışı kesildi:", err)
			close(e.FrameChan)
			return err
		}
		
		frameSize := binary.LittleEndian.Uint32(sizeBuf)
		if frameSize == 0 || frameSize > 10*1024*1024 { 
			close(e.FrameChan)
			return fmt.Errorf("invalid frame size")
		}

		frameData := make([]byte, frameSize)
		if _, err := io.ReadFull(conn, frameData); err != nil {
			close(e.FrameChan)
			return err
		}

		select {
		case e.FrameChan <- frameData:
		default:
		}
	}
}

func (e *Engine) SendInput(ev protocol.InputEvent) error {
	if e.ActiveConn == nil {
		return fmt.Errorf("bağlantı yok")
	}
	data, err := protocol.EncodeInputEvent(ev)
	if err != nil {
		return err
	}
	e.ActiveConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = e.ActiveConn.Write(data)
	return err
}
*/

/*

PERFORMANS AYARI YAPILDI

*/
/*
package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"src-engine/internal/input"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
	"src-engine/internal/video"
)

// Config: Motorun çalışma ayarları
type Config struct {
	Width  int
	Height int
	FPS    int
}

// Engine: Sistemin beyni.
type Engine struct {
	NetMgr          *network.Manager
	InputMgr        input.Manager
	Conf            Config
	FrameChan       chan []byte
	ActiveConn      net.Conn
	RequestApproval func(string) bool
}

func NewEngine(mgr *network.Manager, cfg Config) *Engine {
	im, err := input.NewManager()
	if err != nil {
		fmt.Println("⚠️ Input manager hatası:", err)
	}

	return &Engine{
		NetMgr:    mgr,
		InputMgr:  im,
		Conf:      cfg,
		FrameChan: make(chan []byte, 30),
	}
}

func (e *Engine) SetApprovalCallback(cb func(string) bool) {
	e.RequestApproval = cb
}

// --- INTERNAL HELPERS ---

func writeFull(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func isNetFatal(err error) bool {
	// Basit yaklaşım: timeout/temporary değilse genelde fatal kabul edilebilir.
	// (İstersen net.Error kontrolüyle daha da ayırırız)
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok {
		if ne.Timeout() || ne.Temporary() {
			return false
		}
	}
	return true
}

// --- HOST MODU (Yayıncı) ---

func (e *Engine) StartHost(port int) error {
	listener, err := e.NetMgr.ListenTCP(port)
	if err != nil {
		return err
	}
	fmt.Printf("🎥 HOST MODU BAŞLADI (TCP Port: %d)\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Bağlantı kabul hatası:", err)
			continue
		}

		// 🔥 HOST BOOST: Gelen bağlantının tamponlarını genişlet
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetWriteBuffer(128 * 1024)
			_ = tcpConn.SetReadBuffer(128 * 1024)
			_ = tcpConn.SetNoDelay(true)
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Println("🔒 Bağlantı İsteği Geldi:", remoteIP)

		go e.handleHostConnection(conn)
	}
}

func (e *Engine) handleHostConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("✅ Yayın Akışı Başlatıldı!")

	// 1. INPUT OKUMA (Eski yöntem - Geri uyumluluk için kalsın)
	// Not: Asıl input artık StartDataChannel (44445) üzerinden akıyor.
	go func() {
		header := make([]byte, 14)
		for {
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}
			textLen := int(binary.LittleEndian.Uint16(header[12:14]))
			if textLen < 0 || textLen > 256 {
				return
			}

			payload := make([]byte, 14+textLen)
			copy(payload[:14], header)
			if textLen > 0 {
				if _, err := io.ReadFull(conn, payload[14:]); err != nil {
					return
				}
			}

			ev, err := protocol.DecodeInputEvent(payload)
			if err == nil && e.InputMgr != nil {
				e.InputMgr.Apply(ev)
			}
		}
	}()

	// 2. VIDEO GÖNDERME HAZIRLIĞI
	capturer := video.NewCapturer(0)
	if err := capturer.Start(); err != nil {
		fmt.Println("Capture start error:", err)
		return
	}
	defer capturer.Close()

	realW, realH := capturer.Size()
	targetW, targetH := realW, realH
	if targetW%2 != 0 {
		targetW--
	}
	if targetH%2 != 0 {
		targetH--
	}

	// FPS'i 25'e sabitliyoruz (Altın Oran)
	e.Conf.FPS = 25

	fmt.Printf("🎥 Yayın Ayarı: %dx%d (Native 1080p) @ %d FPS\n", realW, realH, e.Conf.FPS)

	encoder, err := video.NewEncoder(realW, realH, targetW, targetH, e.Conf.FPS)
	if err != nil {
		fmt.Println("Encoder start error:", err)
		return
	}
	defer encoder.Close()

	// --- 🛡️ SENKRONİZASYON & TRAFİK KONTROLÜ ---
	sendChan := make(chan []byte, 5) // küçük tutuyoruz ki şişmesin
	killSwitch := make(chan bool)

	// capture loop çıkarsa writer da bitsin
	defer close(sendChan)

	// A) GÖNDERİCİ (WRITER) - güvenli writeFull + daha doğru hata davranışı
	go func() {
		defer close(killSwitch)

		sizeBuf := make([]byte, 4)
		consecutiveErrors := 0

		for data := range sendChan {
			// Mobil ağlar için hızlı tepki
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

			binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))

			// Header
			if err := writeFull(conn, sizeBuf); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (%d/5): %v\n", consecutiveErrors, err)

				// fatal ise anında çık
				if isNetFatal(err) || consecutiveErrors >= 5 {
					return
				}
				continue
			}

			// Data
			if err := writeFull(conn, data); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (%d/5): %v\n", consecutiveErrors, err)

				if isNetFatal(err) || consecutiveErrors >= 5 {
					return
				}
				continue
			}

			consecutiveErrors = 0
		}
	}()

	// B) YAKALAYICI (CAPTURER LOOP) - backpressure + adaptive bitrate
	interval := time.Second / time.Duration(e.Conf.FPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Adaptive Bitrate
	// Kademeli ve daha stabil: 800 -> 1200 -> 1800 -> 2500
	levels := []int{800, 1200, 1800, 2500}
	levelIdx := 2 // 1800 başlangıç (2000 yerine yakın ama kademeli)
	currentBitrate := levels[levelIdx]
	encoder.SetBitrate(currentBitrate) // ✅ başlangıç bitrate’i gerçekten uygula

	lastAdjustment := time.Now()
	lastCongested := time.Time{}
	lastRelaxed := time.Time{}

	for {
		select {
		case <-killSwitch:
			fmt.Println("🛑 Yayın durduruldu (Writer Kapandı).")
			return
		case <-ticker.C:
		}

		// ✅ KRİTİK: Kuyruk doluyken boşa encode yapma (donmayı kesen ana fix)
		// cap-1'e gelince drop moduna geçiyoruz
		if len(sendChan) >= cap(sendChan)-1 {
			// Sıkışıklık anı
			if lastCongested.IsZero() {
				lastCongested = time.Now()
			}
			// hiçbir şey yapma: capture/encode yok
			continue
		} else {
			// rahat an
			if lastRelaxed.IsZero() {
				lastRelaxed = time.Now()
			}
		}

		// --- 🧠 TRAFİK POLİSİ (ADAPTIVE) ---
		queueSize := len(sendChan)

		// Ayarı çok sık oynatma
		if time.Since(lastAdjustment) > 3*time.Second {
			// Sıkışıklık: queue >= 3
			if queueSize >= 3 {
				// 2 saniyeden uzun sıkışık kaldıysa düşür
				if !lastCongested.IsZero() && time.Since(lastCongested) > 2*time.Second {
					if levelIdx > 0 {
						levelIdx--
						currentBitrate = levels[levelIdx]
						encoder.SetBitrate(currentBitrate)
						fmt.Printf("📉 Ağ tıkandı, kalite düşürülüyor: %d kbps\n", currentBitrate)
					}
					lastAdjustment = time.Now()
					lastCongested = time.Now()
				}
				// rahat sayacını sıfırla
				lastRelaxed = time.Time{}
			} else if queueSize == 0 {
				// Rahatlık: 6 saniye boyunca queue 0 ise yükselt
				if !lastRelaxed.IsZero() && time.Since(lastRelaxed) > 6*time.Second {
					if levelIdx < len(levels)-1 {
						levelIdx++
						currentBitrate = levels[levelIdx]
						encoder.SetBitrate(currentBitrate)
						fmt.Printf("📈 Ağ rahatladı, kalite artırılıyor: %d kbps\n", currentBitrate)
					}
					lastAdjustment = time.Now()
					lastRelaxed = time.Now()
				}
				// sıkışık sayacını sıfırla
				lastCongested = time.Time{}
			} else {
				// orta durum: sayacı resetleme, sadece aşırı oynamayı engelle
				lastCongested = time.Time{}
				lastRelaxed = time.Time{}
			}
		}

		img, err := capturer.Capture()
		if err != nil {
			continue
		}

		h264Data := encoder.Encode(img)
		if len(h264Data) == 0 {
			continue
		}

		select {
		case sendChan <- h264Data:
			// ok
		case <-killSwitch:
			return
		default:
			// 🗑️ DROP FRAME: dolduysa at (latency artmasın, donma olmasın)
		}
	}
}

// --- CLIENT MODU (İzleyici) ---

func (e *Engine) StartClient(targetIP string, port int) error {
	conn, err := e.NetMgr.DialTCP(targetIP, port)
	if err != nil {
		return err
	}

	e.ActiveConn = conn
	fmt.Println("📺 İZLEYİCİ MODU: Bağlantı kuruldu ->", targetIP)

	defer conn.Close()

	sizeBuf := make([]byte, 4)

	// ✅ Buffer reuse: her framede make() yapıp GC şişirmeyelim
	var frameBuf []byte

	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		if _, err := io.ReadFull(conn, sizeBuf); err != nil {
			fmt.Println("⚠️ Veri akışı kesildi:", err)
			close(e.FrameChan)
			return err
		}

		frameSize := binary.LittleEndian.Uint32(sizeBuf)
		if frameSize == 0 || frameSize > 10*1024*1024 {
			close(e.FrameChan)
			return fmt.Errorf("invalid frame size")
		}

		need := int(frameSize)
		if cap(frameBuf) < need {
			frameBuf = make([]byte, need)
		}
		frameData := frameBuf[:need]

		if _, err := io.ReadFull(conn, frameData); err != nil {
			close(e.FrameChan)
			return err
		}

		// FrameChan consumer tarafı yavaşsa drop et (donma yerine akıcılık)
		out := make([]byte, len(frameData))
		copy(out, frameData)

		select {
		case e.FrameChan <- out:
		default:
			// drop
		}
	}
}

func (e *Engine) SendInput(ev protocol.InputEvent) error {
	if e.ActiveConn == nil {
		return fmt.Errorf("bağlantı yok")
	}
	data, err := protocol.EncodeInputEvent(ev)
	if err != nil {
		return err
	}
	_ = e.ActiveConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = e.ActiveConn.Write(data)
	return err
}
*/

/*

MOUSE KLAVYE AKTİF EDİLİYOR 

*/

package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"src-engine/internal/input"
	"src-engine/internal/network"
	"src-engine/internal/protocol"
	"src-engine/internal/video"
)

// Config: Motorun çalışma ayarları
type Config struct {
	Width  int
	Height int
	FPS    int
	RawMode bool
}

// Engine: Sistemin beyni.
type Engine struct {
	NetMgr          *network.Manager
	InputMgr        input.Manager
	Conf            Config
	FrameChan       chan []byte
	ActiveConn      net.Conn
	RequestApproval func(string) bool
}

func NewEngine(mgr *network.Manager, cfg Config) *Engine {
	im, err := input.NewManager()
	if err != nil {
		fmt.Println("⚠️ Input manager hatası:", err)
	}

	return &Engine{
		NetMgr:    mgr,
		InputMgr:  im,
		Conf:      cfg,
		FrameChan: make(chan []byte, 30),
	}
}

func (e *Engine) SetApprovalCallback(cb func(string) bool) {
	e.RequestApproval = cb
}

// --- INTERNAL HELPERS ---

func writeFull(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func isNetFatal(err error) bool {
	// Basit yaklaşım: timeout/temporary değilse genelde fatal kabul edilebilir.
	// (İstersen net.Error kontrolüyle daha da ayırırız)
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok {
		if ne.Timeout() || ne.Temporary() {
			return false
		}
	}
	return true
}

// --- HOST MODU (Yayıncı) ---

func (e *Engine) StartHost(port int) error {
	listener, err := e.NetMgr.ListenTCP(port)
	if err != nil {
		return err
	}
	fmt.Printf("🎥 HOST MODU BAŞLADI (TCP Port: %d)\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Bağlantı kabul hatası:", err)
			continue
		}

		// 🔥 HOST BOOST: Gelen bağlantının tamponlarını genişlet
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetWriteBuffer(128 * 1024)
			_ = tcpConn.SetReadBuffer(128 * 1024)
			_ = tcpConn.SetNoDelay(true)
		}

		remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Println("🔒 Bağlantı İsteği Geldi:", remoteIP)

		go e.handleHostConnection(conn)
	}
}

func (e *Engine) handleHostConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("✅ Yayın Akışı Başlatıldı!")

	// 1. INPUT OKUMA (Geri uyumluluk için kalsın - Artık V2 protokolü devrede)
	// Bu kısım Client'tan gelen klavye/mouse verilerini okur ve InputMgr'a iletir.
	go func() {
		// V2 Header: 14 Byte (protocol.types.go ile uyumlu olmalı)
		// [Dev][Act][Flg][Pad][X][Y][Wh][Key][TextLen]
		header := make([]byte, 14)
		
		for {
			// Header Oku
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}

			// Text uzunluğunu al (Son 2 byte)
			textLen := int(binary.LittleEndian.Uint16(header[12:14]))
			
			// Güvenlik kontrolü
			if textLen < 0 || textLen > 256 {
				fmt.Printf("⚠️ Geçersiz Input Text Boyutu: %d\n", textLen)
				return 
			}

			// Payload'ı oluştur (Header + Text)
			payload := make([]byte, 14+textLen)
			copy(payload[:14], header)

			// Varsa Text'i oku
			if textLen > 0 {
				if _, err := io.ReadFull(conn, payload[14:]); err != nil {
					return
				}
			}

			// Decode et ve uygula
			ev, err := protocol.DecodeInputEvent(payload)
			if err == nil && e.InputMgr != nil {
				// Hata vermeden uygula
				// fmt.Printf("🖱️ Input: %v\n", ev) // Debug için açılabilir
				e.InputMgr.Apply(ev)
			} else if err != nil {
				fmt.Println("⚠️ Input Decode Hatası:", err)
			}
		}
	}()

	// 2. VIDEO GÖNDERME HAZIRLIĞI
	capturer := video.NewCapturer(0)
	if err := capturer.Start(); err != nil {
		fmt.Println("Capture start error:", err)
		return
	}
	defer capturer.Close()

	realW, realH := capturer.Size()
	targetW, targetH := realW, realH
	if targetW%2 != 0 {
		targetW--
	}
	if targetH%2 != 0 {
		targetH--
	}

	// FPS'i 25'e sabitliyoruz (Altın Oran)
	e.Conf.FPS = 25

	fmt.Printf("🎥 Yayın Ayarı: %dx%d (Native 1080p) @ %d FPS\n", realW, realH, e.Conf.FPS)

	encoder, err := video.NewEncoder(realW, realH, targetW, targetH, e.Conf.FPS)
	if err != nil {
		fmt.Println("Encoder start error:", err)
		return
	}
	defer encoder.Close()

	// --- 🛡️ SENKRONİZASYON & TRAFİK KONTROLÜ ---
	sendChan := make(chan []byte, 5) // küçük tutuyoruz ki şişmesin
	killSwitch := make(chan bool)

	// capture loop çıkarsa writer da bitsin
	defer close(sendChan)

	// A) GÖNDERİCİ (WRITER) - güvenli writeFull + daha doğru hata davranışı
	go func() {
		defer close(killSwitch)

		sizeBuf := make([]byte, 4)
		consecutiveErrors := 0

		for data := range sendChan {
			// Mobil ağlar için hızlı tepki
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

			binary.LittleEndian.PutUint32(sizeBuf, uint32(len(data)))

			// Header
			if err := writeFull(conn, sizeBuf); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (%d/5): %v\n", consecutiveErrors, err)

				// fatal ise anında çık
				if isNetFatal(err) || consecutiveErrors >= 5 {
					return
				}
				continue
			}

			// Data
			if err := writeFull(conn, data); err != nil {
				consecutiveErrors++
				fmt.Printf("⚠️ Ağ Hatası (%d/5): %v\n", consecutiveErrors, err)

				if isNetFatal(err) || consecutiveErrors >= 5 {
					return
				}
				continue
			}

			consecutiveErrors = 0
		}
	}()

	// B) YAKALAYICI (CAPTURER LOOP) - backpressure + adaptive bitrate
	interval := time.Second / time.Duration(e.Conf.FPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Adaptive Bitrate
	// Kademeli ve daha stabil: 800 -> 1200 -> 1800 -> 2500
	levels := []int{800, 1200, 1800, 2500}
	levelIdx := 2 // 1800 başlangıç (2000 yerine yakın ama kademeli)
	currentBitrate := levels[levelIdx]
	encoder.SetBitrate(currentBitrate) // ✅ başlangıç bitrate’i gerçekten uygula

	lastAdjustment := time.Now()
	lastCongested := time.Time{}
	lastRelaxed := time.Time{}

	for {
		select {
		case <-killSwitch:
			fmt.Println("🛑 Yayın durduruldu (Writer Kapandı).")
			return
		case <-ticker.C:
		}

		// ✅ KRİTİK: Kuyruk doluyken boşa encode yapma (donmayı kesen ana fix)
		// cap-1'e gelince drop moduna geçiyoruz
		if len(sendChan) >= cap(sendChan)-1 {
			// Sıkışıklık anı
			if lastCongested.IsZero() {
				lastCongested = time.Now()
			}
			// hiçbir şey yapma: capture/encode yok
			continue
		} else {
			// rahat an
			if lastRelaxed.IsZero() {
				lastRelaxed = time.Now()
			}
		}

		// --- 🧠 TRAFİK POLİSİ (ADAPTIVE) ---
		queueSize := len(sendChan)

		// Ayarı çok sık oynatma
		if time.Since(lastAdjustment) > 3*time.Second {
			// Sıkışıklık: queue >= 3
			if queueSize >= 3 {
				// 2 saniyeden uzun sıkışık kaldıysa düşür
				if !lastCongested.IsZero() && time.Since(lastCongested) > 2*time.Second {
					if levelIdx > 0 {
						levelIdx--
						currentBitrate = levels[levelIdx]
						encoder.SetBitrate(currentBitrate)
						fmt.Printf("📉 Ağ tıkandı, kalite düşürülüyor: %d kbps\n", currentBitrate)
					}
					lastAdjustment = time.Now()
					lastCongested = time.Now()
				}
				// rahat sayacını sıfırla
				lastRelaxed = time.Time{}
			} else if queueSize == 0 {
				// Rahatlık: 6 saniye boyunca queue 0 ise yükselt
				if !lastRelaxed.IsZero() && time.Since(lastRelaxed) > 6*time.Second {
					if levelIdx < len(levels)-1 {
						levelIdx++
						currentBitrate = levels[levelIdx]
						encoder.SetBitrate(currentBitrate)
						fmt.Printf("📈 Ağ rahatladı, kalite artırılıyor: %d kbps\n", currentBitrate)
					}
					lastAdjustment = time.Now()
					lastRelaxed = time.Now()
				}
				// sıkışık sayacını sıfırla
				lastCongested = time.Time{}
			} else {
				// orta durum: sayacı resetleme, sadece aşırı oynamayı engelle
				lastCongested = time.Time{}
				lastRelaxed = time.Time{}
			}
		}

		img, err := capturer.Capture()
		if err != nil {
			continue
		}

		h264Data := encoder.Encode(img)
		if len(h264Data) == 0 {
			continue
		}

		select {
		case sendChan <- h264Data:
			// ok
		case <-killSwitch:
			return
		default:
			// 🗑️ DROP FRAME: dolduysa at (latency artmasın, donma olmasın)
		}
	}
}

// --- CLIENT MODU (İzleyici) ---

func (e *Engine) StartClient(targetIP string, port int) error {
	conn, err := e.NetMgr.DialTCP(targetIP, port)
	if err != nil {
		return err
	}

	e.ActiveConn = conn
	fmt.Println("📺 İZLEYİCİ MODU: Bağlantı kuruldu ->", targetIP)

	defer conn.Close()

	sizeBuf := make([]byte, 4)

	// ✅ Buffer reuse: her framede make() yapıp GC şişirmeyelim
	var frameBuf []byte

	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		if _, err := io.ReadFull(conn, sizeBuf); err != nil {
			fmt.Println("⚠️ Veri akışı kesildi:", err)
			close(e.FrameChan)
			return err
		}

		frameSize := binary.LittleEndian.Uint32(sizeBuf)
		if frameSize == 0 || frameSize > 10*1024*1024 {
			close(e.FrameChan)
			return fmt.Errorf("invalid frame size")
		}

		need := int(frameSize)
		if cap(frameBuf) < need {
			frameBuf = make([]byte, need)
		}
		frameData := frameBuf[:need]

		if _, err := io.ReadFull(conn, frameData); err != nil {
			close(e.FrameChan)
			return err
		}

		// FrameChan consumer tarafı yavaşsa drop et (donma yerine akıcılık)
		out := make([]byte, len(frameData))
		copy(out, frameData)

		select {
		case e.FrameChan <- out:
		default:
			// drop
		}
	}
}

func (e *Engine) SendInput(ev protocol.InputEvent) error {
	if e.ActiveConn == nil {
		return fmt.Errorf("bağlantı yok")
	}
	data, err := protocol.EncodeInputEvent(ev)
	if err != nil {
		return err
	}
	_ = e.ActiveConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = e.ActiveConn.Write(data)
	return err
}