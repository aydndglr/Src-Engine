//go:build windows
package video

/*
#cgo LDFLAGS: -ld3d11 -ldxgi
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <stdio.h>

// --- C TARAFI: DXGI (DirectX) YÖNETİMİ ---
// COM Nesnelerini C ile yönetmek biraz verbose (sözlü) olur,
// çünkü C++ class'ları yerine vtable pointer'ları kullanırız.

typedef struct {
    ID3D11Device* device;
    ID3D11DeviceContext* context;
    IDXGIOutputDuplication* duplication;
    ID3D11Texture2D* stagingTex; // CPU'nun okuyabildiği ara doku
    int                     width;
    int                     height;
    int                     attached;
} DxgiManager;

// Hata ayıklama için basit log
void log_err(const char* msg, HRESULT hr) {
    // printf("[DXGI ERROR] %s (HR: 0x%X)\n", msg, (unsigned int)hr);
}

// 1. INIT: DirectX Cihazını ve Çoğaltıcıyı Başlat
DxgiManager* dxgi_init(int displayIndex) {
    HRESULT hr;
    DxgiManager* m = (DxgiManager*)calloc(1, sizeof(DxgiManager));
    
    // Feature levels
    D3D_FEATURE_LEVEL featureLevels[] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
        D3D_FEATURE_LEVEL_9_1
    };
    D3D_FEATURE_LEVEL featureLevel;

    // D3D11 Device oluştur
    hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, 
                           featureLevels, 4, D3D11_SDK_VERSION, 
                           &m->device, &featureLevel, &m->context);
    if (FAILED(hr)) {
        log_err("D3D11CreateDevice failed", hr);
        free(m); return NULL;
    }

    // IDXGIDevice al
    IDXGIDevice* dxgiDevice = NULL;
    hr = m->device->lpVtbl->QueryInterface(m->device, &IID_IDXGIDevice, (void**)&dxgiDevice);
    if (FAILED(hr)) return NULL;

    // IDXGIAdapter al
    IDXGIAdapter* dxgiAdapter = NULL;
    hr = dxgiDevice->lpVtbl->GetParent(dxgiDevice, &IID_IDXGIAdapter, (void**)&dxgiAdapter);
    dxgiDevice->lpVtbl->Release(dxgiDevice);
    if (FAILED(hr)) return NULL;

    // IDXGIOutput al (Hangi monitör?)
    IDXGIOutput* dxgiOutput = NULL;
    hr = dxgiAdapter->lpVtbl->EnumOutputs(dxgiAdapter, displayIndex, &dxgiOutput);
    dxgiAdapter->lpVtbl->Release(dxgiAdapter);
    if (FAILED(hr)) {
        log_err("Monitor index not found", hr);
        return NULL;
    }

    // IDXGIOutput1 arayüzüne geç (Duplication için gerekli)
    IDXGIOutput1* dxgiOutput1 = NULL;
    hr = dxgiOutput->lpVtbl->QueryInterface(dxgiOutput, &IID_IDXGIOutput1, (void**)&dxgiOutput1);
    dxgiOutput->lpVtbl->Release(dxgiOutput);
    if (FAILED(hr)) return NULL;

    // DuplicateOutput (Sihirli kısım)
    hr = dxgiOutput1->lpVtbl->DuplicateOutput(dxgiOutput1, (IUnknown*)m->device, &m->duplication);
    dxgiOutput1->lpVtbl->Release(dxgiOutput1);
    if (FAILED(hr)) {
        // Genelde izin yoksa veya desteklenmiyorsa burası patlar
        log_err("DuplicateOutput failed (Check permissions/GPU driver)", hr);
        return NULL;
    }

    // Çözünürlüğü al
    DXGI_OUTDUPL_DESC desc;
    m->duplication->lpVtbl->GetDesc(m->duplication, &desc);
    m->width = desc.ModeDesc.Width;
    m->height = desc.ModeDesc.Height;
    m->attached = 1;

    return m;
}

// 2. CAPTURE: Bir kare yakala ve buffer'a kopyala
// Dönüş: 0=OK, 1=Timeout(Değişiklik yok), 2=Hata/Lost
int dxgi_capture(DxgiManager* m, uint8_t* destBuf, int destSize) {
    if (!m || !m->attached) return 2;

    HRESULT hr;
    IDXGIResource* desktopRes = NULL;
    DXGI_OUTDUPL_FRAME_INFO frameInfo;

    // Bir sonraki kareyi bekle (Timeout: 100ms)
    // Ekran değişmediyse Timeout döner, bu performans için iyidir.
    hr = m->duplication->lpVtbl->AcquireNextFrame(m->duplication, 100, &frameInfo, &desktopRes);
    
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
        return 1; // Değişiklik yok
    }
    if (FAILED(hr)) {
        // Bağlantı kopmuş olabilir (çözünürlük değişti, ctrl+alt+del vb.)
        if (hr == DXGI_ERROR_ACCESS_LOST) return 2;
        return 2;
    }

    // Görüntüyü Texture2D olarak al
    ID3D11Texture2D* gpuTex = NULL;
    hr = desktopRes->lpVtbl->QueryInterface(desktopRes, &IID_ID3D11Texture2D, (void**)&gpuTex);
    desktopRes->lpVtbl->Release(desktopRes);
    if (FAILED(hr)) {
        m->duplication->lpVtbl->ReleaseFrame(m->duplication);
        return 2;
    }

    // Staging Texture (CPU'nun okuyabileceği texture) yoksa veya boyutu değiştiyse oluştur
    if (m->stagingTex == NULL) {
        D3D11_TEXTURE2D_DESC desc;
        gpuTex->lpVtbl->GetDesc(gpuTex, &desc);
        
        desc.Usage = D3D11_USAGE_STAGING;
        desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        desc.BindFlags = 0;
        desc.MiscFlags = 0;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.SampleDesc.Count = 1;

        hr = m->device->lpVtbl->CreateTexture2D(m->device, &desc, NULL, &m->stagingTex);
        if (FAILED(hr)) {
            gpuTex->lpVtbl->Release(gpuTex);
            m->duplication->lpVtbl->ReleaseFrame(m->duplication);
            return 2;
        }
    }

    // GPU Belleğinden Staging Belleğine Kopyala
    m->context->lpVtbl->CopyResource(m->context, (ID3D11Resource*)m->stagingTex, (ID3D11Resource*)gpuTex);
    gpuTex->lpVtbl->Release(gpuTex);

    // Staging Belleğini Map et (CPU okuması için kilitle)
    D3D11_MAPPED_SUBRESOURCE mapped;
    hr = m->context->lpVtbl->Map(m->context, (ID3D11Resource*)m->stagingTex, 0, D3D11_MAP_READ, 0, &mapped);
    if (SUCCEEDED(hr)) {
        // Veriyi Go tarafındaki buffer'a kopyala
        // Dikkat: Pitch (stride) ekran genişliğinden farklı olabilir, satır satır kopyalamalıyız.
        uint8_t* src = (uint8_t*)mapped.pData;
        uint8_t* dst = destBuf;
        int rowLen = m->width * 4; // RGBA

        for (int y = 0; y < m->height; y++) {
            memcpy(dst, src, rowLen);
            dst += rowLen;
            src += mapped.RowPitch;
        }

        m->context->lpVtbl->Unmap(m->context, (ID3D11Resource*)m->stagingTex, 0);
    }

    m->duplication->lpVtbl->ReleaseFrame(m->duplication);
    return 0;
}

// 3. CLEANUP
void dxgi_release(DxgiManager* m) {
    if (!m) return;
    if (m->stagingTex) m->stagingTex->lpVtbl->Release(m->stagingTex);
    if (m->duplication) m->duplication->lpVtbl->Release(m->duplication);
    if (m->context) m->context->lpVtbl->Release(m->context);
    if (m->device) m->device->lpVtbl->Release(m->device);
    free(m);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"image"
	"sync"
	"unsafe"
)

// Capturer Interface
type Capturer interface {
	Start() error
	Capture() (*image.RGBA, error)
	Size() (int, int)
	Close()
}

// DxgiCapturer: Windows DirectX tabanlı yakalayıcı
type DxgiCapturer struct {
	index     int
	mgr       *C.DxgiManager
	width     int
	height    int
	lastImage *image.RGBA // Değişiklik olmazsa son resmi döndürürüz
	mu        sync.Mutex
}

func NewCapturer(displayIndex int) Capturer {
	return &DxgiCapturer{
		index: displayIndex,
	}
}

func (c *DxgiCapturer) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// C tarafındaki Init fonksiyonunu çağır
	ptr := C.dxgi_init(C.int(c.index))
	if ptr == nil {
		return fmt.Errorf("DXGI başlatılamadı (GPU sürücülerini kontrol et veya ekran takılı değil)")
	}

	c.mgr = ptr
	c.width = int(ptr.width)
	c.height = int(ptr.height)

	// Boş bir başlangıç görseli oluştur
	c.lastImage = image.NewRGBA(image.Rect(0, 0, c.width, c.height))

	return nil
}

func (c *DxgiCapturer) Capture() (*image.RGBA, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mgr == nil {
		return nil, errors.New("capturer not started")
	}

	// Go'daki buffer'ın pointer'ını C'ye veriyoruz
	destPtr := unsafe.Pointer(&c.lastImage.Pix[0])
	destSize := C.int(len(c.lastImage.Pix))

	// Yakalama isteği gönder
	result := C.dxgi_capture(c.mgr, (*C.uint8_t)(destPtr), destSize)

	// Sonuç Analizi
	if result == 0 {
		// Başarılı: Yeni görüntü buffer'a yazıldı, lastImage güncel.
		return c.lastImage, nil
	} else if result == 1 {
		// Timeout: Ekran değişmedi. Eski resmi aynen döndür.
		return c.lastImage, nil
	} else {
		// Hata
		return nil, errors.New("DXGI capture failed or device lost")
	}
}

func (c *DxgiCapturer) Size() (int, int) {
	return c.width, c.height
}

func (c *DxgiCapturer) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mgr != nil {
		C.dxgi_release(c.mgr)
		c.mgr = nil
	}
}