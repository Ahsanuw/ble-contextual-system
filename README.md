# BLE Room Presence System

Energy-efficient, context-aware room presence detection using **BLE RSSI** to determine which room a person is in and automatically control lights and AC units.

## How It Works

A person carries a small BLE beacon (ESP32). Fixed sensor nodes (ESP32-C3) in each room listen for the beacon's signal strength (RSSI). The room with the strongest signal is where the person is. Devices in that room turn ON; all others turn OFF.

```
[Beacon] --BLE adv--> [Sensor Node 1 (Living Room)]
                  --> [Sensor Node 2 (Bedroom)]   --> [MQTT Broker] --> [Controller] --> [Relays]
                  --> [Sensor Node 3 (Kitchen)]
```

## Architecture

Three separate ESP-IDF applications under `apps/`, plus a Python monitoring tool:

| Component | Hardware | Role |
|-----------|----------|------|
| **Beacon** | ESP32 | Broadcasts authenticated, rolling-ID BLE advertising packets |
| **Sensor** | ESP32-C3 | Scans for beacon packets, verifies HMAC, applies Kalman filter, publishes to MQTT |
| **Controller** | ESP32 | Subscribes to MQTT, selects active room, drives relays, serves web dashboard |
| **Monitor** | Laptop (Python) | Testing/debugging tool using Bleak + Rich |

## Repository Structure

```
apps/
  beacon/       -- BLE beacon firmware (ESP32)
  sensor/       -- Room sensor node firmware (ESP32-C3)
  controller/   -- Central controller firmware (ESP32)
docs/           -- Documentation
monitoring-tools/
  rssi-scanner.py   -- Python BLE scanner/monitor
  requirment.txt    -- Python dependencies
```

## Prerequisites

- **ESP-IDF v5.x** with `IDF_PATH` set
- Python 3.8+ for the monitor tool
- Mosquitto MQTT broker on the local network

## Quick Start

### 1. Build & Flash Beacon (ESP32)

```bash
cd apps/beacon
idf.py set-target esp32
# Edit DEVICE_ID and SECRET_KEY in main/main.c
idf.py build && idf.py -p /dev/ttyUSB0 flash monitor
```

### 2. Build & Flash Sensor Node (ESP32-C3)

```bash
cd apps/sensor
idf.py set-target esp32c3
# Edit WIFI_SSID, WIFI_PASS, MQTT_BROKER_URI, NODE_ID, SECRET_KEY
idf.py build && idf.py -p /dev/ttyUSB1 flash monitor
```

### 3. Build & Flash Controller (ESP32)

```bash
cd apps/controller
idf.py set-target esp32
# Edit WIFI_SSID, WIFI_PASS, MQTT_BROKER_URI, relay GPIOs
idf.py build && idf.py -p /dev/ttyUSB2 flash monitor
```

### 4. Start MQTT Broker

```bash
mosquitto -v
```

### 5. Python Monitor (for testing without hardware sensors)

```bash
cd monitoring-tools
pip install -r requirment.txt
python rssi-scanner.py --target hackathon
```

### 6. Access Dashboard

Open `http://<controller-ip>/` in a browser.

## Configuration

### Beacon (`apps/beacon/main/main.c`)

```c
#define DEVICE_ID           0x01       // Unique per beacon
#define SECRET_KEY          "hackathon2026"  // Must match all devices
#define ROLL_INTERVAL_MS    60000      // Rolling ID refresh period
```

### Sensor Node (`apps/sensor/main/main.c`)

```c
#define WIFI_SSID           "YourSSID"
#define WIFI_PASS           "YourPassword"
#define MQTT_BROKER_URI     "mqtt://192.168.1.100:1883"
#define NODE_ID             1          // Unique per sensor node
#define SECRET_KEY          "hackathon2026"  // Must match beacon
#define RSSI_THRESHOLD_ROOM (-65)      // Calibrate per environment
#define RSSI_THRESHOLD_NEAR (-80)
```

### Controller (`apps/controller/main/main.c`)

```c
#define WIFI_SSID           "YourSSID"
#define WIFI_PASS           "YourPassword"
#define MQTT_BROKER_URI     "mqtt://192.168.1.100:1883"
#define NUM_ROOMS           3
#define HYSTERESIS_DBM      5.0        // Prevents rapid room switching
```

## Data Flow

### BLE Payload (11 bytes)

```
[magic(0xBE)][version(0x01)][device_id][timestamp(4B LE)][hmac(4B)]
```

- Broadcast as manufacturer-specific data (type 0xFF) with company ID 0x05AC
- Non-connectable advertising at 100-120ms intervals
- HMAC-SHA256 truncated to 4 bytes for authentication
- Rolling ID changes every 60 seconds for privacy

### MQTT Topic

```
presence/node{NODE_ID}/beacon/{device_id}
```

### MQTT Payload (JSON)

```json
{
  "node_id": 1,
  "device_id": 1,
  "rssi_raw": -62,
  "rssi_filtered": -63.4,
  "state": "ROOM",
  "hmac_ok": true,
  "beacon_ts": 121,
  "timeout": false
}
```

### Room Classification

| Condition | State |
|-----------|-------|
| RSSI > -65 dBm | ROOM (person is here) |
| RSSI > -80 dBm | NEAR (person is close) |
| RSSI <= -80 dBm | FAR (person is far) |
| No packet for 5s | NO_SIGNAL (out of range) |

### Controller Decision

1. Discard rooms with no data, timeout, NO_SIGNAL/FAR state, or unverified HMAC
2. Select room with highest `rssi_filtered`
3. Apply 5 dBm hysteresis to prevent flickering
4. Turn ON relays in active room, OFF in all others

## Key Features

| Feature | Implementation |
|---------|---------------|
| **Rolling ID** | Beacon identity changes every 60s for privacy |
| **HMAC Auth** | 4-byte truncated HMAC-SHA256 prevents spoofed beacons |
| **Kalman Filter** | 1D scalar Kalman filter smooths noisy RSSI |
| **Hysteresis** | 5 dBm threshold prevents rapid room switching |
| **Self-Recovery** | Watchdog restarts advertising if stopped unexpectedly |
| **Energy Tracking** | Real-time kWh, cost (IDR), and CO2 savings |
| **Web Dashboard** | Self-contained HTML/JS, no CDN dependencies |
| **Thread Safety** | FreeRTOS mutex protects shared beacon state |

## Calibration

RSSI thresholds are environment-dependent. Calibrate per deployment:

1. Place beacon in center of target room
2. Run `python rssi-scanner.py --target hackathon` for 60s
3. Note `rssi_filtered` value as ROOM threshold (use -5 dBm safety margin)
4. Move beacon to adjacent room and note RSSI for NEAR/FAR boundary

### Wall Attenuation Reference

| Material | Attenuation |
|----------|------------|
| Concrete | -15 to -20 dBm per wall |
| Gypsum/wood | -5 to -10 dBm per wall |
| Human body | -3 to -5 dBm |

## API Endpoints (Controller)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/api/state` | GET | JSON API with room states, energy data, active room |

## Energy Calculation

- AC power: 900W (1 PK)
- LED lamp: 20W
- PLN rate: Rp 1,444/kWh
- CO2 factor: 785 g/kWh (Indonesia grid)
- Savings = (NUM_ROOMS - 1) × power × time (assumes all rooms ON without system)

## Debugging

### HMAC always fails
- Check `SECRET_KEY` matches across all devices
- Check `COMPANY_ID` (0x05AC) matches everywhere
- Verify payload length >= 11 bytes
- Confirm byte order (timestamp is little-endian uint32)

### Sensor not receiving beacon
- Both on BLE (2.4GHz)? No interference?
- Check beacon serial log for advertising status
- Try scan_window = scan_interval (100% duty cycle) for debugging

### MQTT not connecting
- Broker IP correct in `MQTT_BROKER_URI`?
- Same WiFi network?
- Firewall blocking port 1883?

### RSSI flickering
- Normal BLE behavior. Mitigation:
- Increase `KALMAN_R` for more smoothing
- Increase `HYSTERESIS_DBM` in controller
- Move devices away from WiFi routers

## Shared Constants (MUST match across all devices)

| Constant | Value |
|----------|-------|
| `SECRET_KEY` | `"hackathon2026"` |
| `COMPANY_ID` | `0x05AC` |
| `PAYLOAD_MAGIC` | `0xBE` |

## Limitations

- Single user tracking (one beacon at a time)
- RSSI noise causes ±3-5 dBm fluctuation even with Kalman filter
- 4-byte truncated HMAC is not production-grade crypto
- No TLS on MQTT (local network only)
- No BLE encryption (advertising is broadcast)

## License

Hackathon project — internal use.
