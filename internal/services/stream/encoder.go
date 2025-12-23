package stream

/*
#cgo LDFLAGS: -lx264
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <x264.h>

// --- C TARAFI: HIZLI DOWNSCALE + YUV DÖNÜŞÜMÜ ---
static void rgba_to_yuv420_scaled(uint8_t *rgba, uint8_t *y_plane, uint8_t *u_plane, uint8_t *v_plane,
                                  int in_w, int in_h, int out_w, int out_h, int stride) {
    int uv_index = 0;
    int y_index = 0;
    for (int j = 0; j < out_h; j++) {
        int src_y = (j * in_h) / out_h;
        uint8_t *row_start = rgba + (src_y * stride);
        for (int i = 0; i < out_w; i++) {
            int src_x = (i * in_w) / out_w;
            int offset = src_x * 4;
            uint8_t b = row_start[offset + 0];
            uint8_t g = row_start[offset + 1];
            uint8_t r = row_start[offset + 2];

            int y_val = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
            if (y_val < 0) y_val = 0; else if (y_val > 255) y_val = 255;
            y_plane[y_index++] = (uint8_t)y_val;

            if ((j % 2) == 0 && (i % 2) == 0) {
                int u_val = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                int v_val = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
                if (u_val < 0) u_val = 0; else if (u_val > 255) u_val = 255;
                if (v_val < 0) v_val = 0; else if (v_val > 255) v_val = 255;
                u_plane[uv_index] = (uint8_t)u_val;
                v_plane[uv_index] = (uint8_t)v_val;
                uv_index++;
            }
        }
    }
}

static x264_t* init_encoder(int width, int height, int fps, x264_param_t* param) {
    if (x264_param_default_preset(param, "superfast", "zerolatency") < 0) return NULL;

    param->i_width  = width;
    param->i_height = height;
    param->i_fps_num = fps;
    param->i_fps_den = 1;

    // Low-latency ayarları
    param->b_intra_refresh = 1;
    param->i_keyint_max = 25;
    param->i_keyint_min = 12;
    param->i_slice_max_size = 1000;

    // ABR + VBV
    param->rc.i_rc_method = X264_RC_ABR;
    param->rc.i_bitrate = 1800;      // Başlangıç
    param->rc.i_vbv_max_bitrate = 2200; 
    param->rc.i_vbv_buffer_size = 1200; 

    param->rc.i_qp_min = 20;
    param->rc.i_qp_max = 51;
    param->b_repeat_headers = 1;
    param->b_annexb = 1;

    x264_param_apply_profile(param, "baseline");
    param->i_log_level = X264_LOG_NONE;

    return x264_encoder_open(param);
}

// Canlı Bitrate Güncelleme
static void update_bitrate(x264_t *h, x264_param_t *param, int bitrate) {
    if (bitrate <= 0) return;
    param->rc.i_bitrate = bitrate;
    param->rc.i_vbv_max_bitrate = bitrate + 500;
    param->rc.i_vbv_buffer_size = bitrate / 2;
    x264_encoder_reconfig(h, param);
}
*/
import "C"

import (
	"errors"
	"image"
	"sync"
	"time"
	"unsafe"
)

type Encoder struct {
	InWidth, InHeight   int
	OutWidth, OutHeight int
	FPS                 int

	handle *C.x264_t
	param  C.x264_param_t
	picIn  C.x264_picture_t
	picOut C.x264_picture_t

	frameIndex int64

	mu          sync.Mutex
	lastReconf  time.Time
	lastBitrate int
}

func NewEncoder(inW, inH, outW, outH, fps int) (*Encoder, error) {
	if outW == 0 || outH == 0 {
		outW, outH = inW, inH
	}
	// Çözünürlük çift sayı olmalı
	if outW%2 != 0 {
		outW--
	}
	if outH%2 != 0 {
		outH--
	}

	e := &Encoder{
		InWidth:   inW,
		InHeight:  inH,
		OutWidth:  outW,
		OutHeight: outH,
		FPS:       fps,
	}

	e.handle = C.init_encoder(C.int(outW), C.int(outH), C.int(fps), &e.param)
	if e.handle == nil {
		return nil, errors.New("x264 başlatılamadı")
	}

	C.x264_picture_alloc(&e.picIn, C.X264_CSP_I420, C.int(outW), C.int(outH))

	e.lastBitrate = int(e.param.rc.i_bitrate)
	e.lastReconf = time.Now()

	return e, nil
}

// SetBitrate: Yayının kalitesini canlı olarak değiştirir.
func (e *Encoder) SetBitrate(kbps int) {
	if kbps < 300 {
		kbps = 300
	}
	if kbps > 8000 {
		kbps = 8000
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.handle == nil {
		return
	}

	// Çok sık güncelleme yapma (750ms koruma)
	if time.Since(e.lastReconf) < 750*time.Millisecond {
		return
	}

	if kbps == e.lastBitrate {
		return
	}

	C.update_bitrate(e.handle, &e.param, C.int(kbps))
	e.lastBitrate = kbps
	e.lastReconf = time.Now()
}

func (e *Encoder) Encode(img *image.RGBA) []byte {
	if img == nil {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.handle == nil {
		return nil
	}

	// RGBA -> YUV420 Dönüşümü
	srcPtr := unsafe.Pointer(&img.Pix[0])
	yPtr := unsafe.Pointer(e.picIn.img.plane[0])
	uPtr := unsafe.Pointer(e.picIn.img.plane[1])
	vPtr := unsafe.Pointer(e.picIn.img.plane[2])

	C.rgba_to_yuv420_scaled(
		(*C.uint8_t)(srcPtr), (*C.uint8_t)(yPtr), (*C.uint8_t)(uPtr), (*C.uint8_t)(vPtr),
		C.int(e.InWidth), C.int(e.InHeight),
		C.int(e.OutWidth), C.int(e.OutHeight),
		C.int(img.Stride),
	)

	e.picIn.i_pts = C.int64_t(e.frameIndex)
	e.frameIndex++

	var nals *C.x264_nal_t
	var iNals C.int

	frameSize := C.x264_encoder_encode(e.handle, &nals, &iNals, &e.picIn, &e.picOut)
	if frameSize <= 0 || iNals <= 0 || nals == nil {
		return nil
	}

	// NAL Paketlerini Go Slice'ına kopyala
	nalSlice := unsafe.Slice(nals, int(iNals))
	total := 0
	for i := 0; i < int(iNals); i++ {
		if nalSlice[i].i_payload > 0 {
			total += int(nalSlice[i].i_payload)
		}
	}
	if total == 0 {
		return nil
	}

	out := make([]byte, 0, total)
	for i := 0; i < int(iNals); i++ {
		n := int(nalSlice[i].i_payload)
		if n <= 0 || nalSlice[i].p_payload == nil {
			continue
		}
		chunk := unsafe.Slice((*byte)(unsafe.Pointer(nalSlice[i].p_payload)), n)
		out = append(out, chunk...)
	}

	return out
}

func (e *Encoder) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.handle != nil {
		C.x264_encoder_close(e.handle)
		C.x264_picture_clean(&e.picIn)
		e.handle = nil
	}
}