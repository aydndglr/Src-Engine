# SRConnect

**SRConnect** is a **high-performance, ultra low-latency**, **peer-to-peer (P2P)** remote desktop control software developed using **Go** and **Electron**.

Unlike traditional solutions, SRConnect eliminates data processing bottlenecks by leveraging a **custom Ring Buffer architecture** combined with a **hardware-accelerated WebCodecs API + Canvas rendering engine**.

At its core, SRConnect operates on a **private, application-level VPN infrastructure**, designed specifically for real-time media streaming and bidirectional input control.

---

## 🌟 Key Features

### ⚡ Go-Based Engine (SRCEngine)
The backend engine is written in Go and heavily optimized using **CGO, C, and Assembly-level techniques**, enabling efficient screen capture and video encoding with minimal CPU overhead.

### 🎮 WebCodecs & Canvas Rendering
Instead of relying on the standard `<video>` element, SRConnect decodes **raw H.264 streams directly on the GPU** via the **WebCodecs API**, rendering frames instantly onto an **HTML5 Canvas**.  
This design virtually eliminates CPU-bound rendering costs.

### 🛡️ Ring Buffer Architecture
To avoid JavaScript Garbage Collection (GC) stalls, SRConnect uses a **Zero-Allocation circular Ring Buffer system**.  
This ensures stable memory usage even during long-running sessions (10+ hours).

### 🌐 Private P2P VPN Networking
SRConnect establishes connections over a **custom-built, secure P2P VPN layer**:
- No port forwarding required
- Seamless operation behind NAT and firewalls
- Encrypted point-to-point tunnels optimized for low latency
- Designed specifically for real-time video and input traffic

### 🖱️ Precision Input Control
By leveraging native **Windows APIs (ScanCodes & Absolute Coordinates)**, SRConnect delivers **pixel-perfect mouse and keyboard input**, even across varying resolutions and DPI settings.

---

## 🏗️ Architecture

SRConnect follows a **Sidecar (Companion Process)** architecture, separating the real-time engine from the UI layer.

```mermaid
graph TD
    A[Go Backend - SRCEngine] -->|Encrypted P2P Tunnel| B[Electron Frontend]
    B -->|Input Events V2| A

    subgraph BACKEND [Backend]
        A1[DXGI Screen Capture] --> A2[x264 Encoder]
        A2 --> A3[Private P2P VPN Layer]
    end

    subgraph FRONTEND [Frontend]
        B1[Ring Buffer] --> B2[WebCodecs API]
        B2 --> B3[HTML5 Canvas]
    end

```

### Backend (Go)
- Captures the desktop using **Windows DXGI**
- Encodes video using **x264**
- Streams data through a **private encrypted P2P VPN tunnel**

### Frontend (Electron)
- Receives raw video over a local secure bridge
- Writes frames into the Ring Buffer
- Decodes frames using WebCodecs
- Renders directly to Canvas

---

## 🛠️ Build & Setup

### Requirements
- Go **v1.21+**
- Node.js **v18+** & NPM
- GCC  
  - **MinGW-w64** required on Windows for CGO

---

### 1️⃣ Build the Backend (Engine)

```powershell
cd src-engine

# Windows build (no GUI window):
go build -ldflags="-H windowsgui -s -w" -o SRCEngine.exe ./cmd/engine
```

Copy the generated `SRCEngine.exe` into the root directory of the Electron project.

---

## 🖥️ Usage

- On startup, SRConnect automatically launches in **Host (Broadcaster)** mode
- A unique **secure session ID** is generated

### To connect
Enter the target session ID and click **Connect**.

---

## 🔧 Engine Parameters (Manual)

```bash
./SRCEngine.exe -key "AUTH_KEY" -ui-port 9000 -connect "TARGET_IP" -raw
```

**Parameters:**
- `-raw`  
  Outputs headerless raw video (useful for VLC / FFplay testing)

---

## 📂 Project Structure

- `cmd/engine/` – Go engine entry point
- `internal/video/` – DXGI capture & x264 encoder (CGO)
- `internal/network/` – Private P2P VPN & transport layer
- `internal/input/` – Keyboard & mouse simulation (Windows / Linux)

---

## 🤝 Contributing

---

## 📄 License

This project is licensed under the **MIT License**.  
See the `LICENSE` file for details.
