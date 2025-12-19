//go:build !windows

package video

import (
	"errors"
	"image"
	"time"
)

// Windows dışı sistemler için geçici yakalayıcı (Stub)
// İleride buraya Linux/X11/Wayland kodu gelecek.
type StubCapturer struct {
	width  int
	height int
}

func NewCapturer(displayIndex int) Capturer {
	return &StubCapturer{width: 1920, height: 1080}
}

func (c *StubCapturer) Start() error {
	return nil
}

func (c *StubCapturer) Capture() (*image.RGBA, error) {
	// CPU'yu yormamak için biraz bekle (Simüle edilmiş FPS)
	time.Sleep(33 * time.Millisecond)
	
	// Boş/Siyah bir görüntü döndür
	// İleride buraya X11 Screenshot kodu gelecek
	img := image.NewRGBA(image.Rect(0, 0, c.width, c.height))
	return img, nil
}

func (c *StubCapturer) Size() (int, int) {
	return c.width, c.height
}

func (c *StubCapturer) Close() {
}