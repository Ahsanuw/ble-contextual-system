# Build & Deployment Guide

## Prerequisites

```bash
# Install ESP-IDF v5.x
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh
source export.sh

# Install Mosquitto MQTT broker
sudo apt install mosquitto mosquitto-clients

# Python dependencies for monitor tool
pip install bleak rich
```

## Build Firmware

### Beacon (ESP32)

```bash
cd apps/beacon
idf.py set-target esp32
idf.py menuconfig
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

### Sensor Node (ESP32-C3)

```bash
cd apps/sensor
idf.py set-target esp32c3
idf.py menuconfig
idf.py build
idf.py -p /dev/ttyUSB1 flash monitor
```

### Controller (ESP32)

```bash
cd apps/controller
idf.py set-target esp32
idf.py menuconfig
idf.py build
idf.py -p /dev/ttyUSB2 flash monitor
```

## Configuration Checklist

### Beacon
- [ ] `DEVICE_ID` — unique per beacon (0x01-0xFF)
- [ ] `SECRET_KEY` — must match all sensor nodes

### Sensor Node
- [ ] `WIFI_SSID` / `WIFI_PASS` — WiFi credentials
- [ ] `MQTT_BROKER_URI` — e.g. `mqtt://192.168.1.100:1883`
- [ ] `NODE_ID` — unique per sensor (1, 2, 3...)
- [ ] `SECRET_KEY` — must match beacon
- [ ] `RSSI_THRESHOLD_ROOM` / `RSSI_THRESHOLD_NEAR` — calibrate per environment

### Controller
- [ ] `WIFI_SSID` / `WIFI_PASS` — WiFi credentials
- [ ] `MQTT_BROKER_URI` — must match sensor's broker
- [ ] `NUM_ROOMS` — number of sensor nodes deployed
- [ ] Relay GPIO pins — `RELAY_LIGHT[]` and `RELAY_AC[]`

## Hardware Wiring

### Beacon (ESP32)
- No external connections needed
- LED on GPIO 2 (onboard)
- Powered via USB or LiPo battery (~80mA advertising)

### Sensor Node (ESP32-C3)
- No external BLE connections
- LED on GPIO 8 (onboard)
- Powered via USB or 5V supply (~120mA WiFi + BLE scanning)

### Controller Relay Connections

| Room | Light GPIO | AC GPIO |
|------|-----------|---------|
| 1 (Living Room) | GPIO 18 | GPIO 19 |
| 2 (Bedroom) | GPIO 21 | GPIO 42 |
| 3 (Kitchen) | GPIO 43 | GPIO 45 |

Relay wiring: IN pin to controller GPIO, COM + NO in series with device power. HIGH = relay closed = device ON.

### MQTT Broker
- Install: `sudo apt install mosquitto`
- Start: `mosquitto -v` (verbose mode)
- Default port: 1883

## Testing

### Subscribe to all MQTT topics
```bash
mosquitto_sub -h 192.168.1.100 -t "presence/#" -v
```

### Python monitor (laptop BLE scan)
```bash
cd monitoring-tools
python rssi-scanner.py --target hackathon
python rssi-scanner.py --target hackathon --log   # CSV logging
python rssi-scanner.py --room -60 --near -75      # Custom thresholds
```

### Publish test MQTT message
```bash
mosquitto_pub -h 192.168.1.100 -t "presence/node1/beacon/1" -m '{"node_id":1,"device_id":1,"rssi_filtered":-62.0,"state":"ROOM","hmac_ok":true,"timeout":false}'
```

## Calibration Procedure

1. Place beacon in center of target room
2. Place sensor node at intended installation position
3. Run Python monitor for 60 seconds
4. Note `rssi_filtered` value = ROOM threshold (use -5 dBm safety margin)
5. Move beacon to adjacent room, note RSSI for NEAR/FAR boundary
6. Set thresholds accordingly

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| No beacons detected | SECRET_KEY mismatch | Verify across all devices |
| No beacons detected | COMPANY_ID mismatch | Must be 0x05AC everywhere |
| Double "Advertising active" | Watchdog + roll timer conflict | Fixed by s_rolling flag |
| Sensor not receiving | BLE interference | Check 2.4GHz environment |
| MQTT not connecting | Wrong broker URI | Verify IP and port 1883 |
| MQTT not connecting | Firewall | Allow port 1883 |
| RSSI flickering | Normal BLE noise | Increase KALMAN_R or HYSTERESIS_DBM |
