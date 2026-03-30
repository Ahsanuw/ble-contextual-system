/*/*
 * ============================================================
 *  SENSOR NODE FIRMWARE — Energy-Efficient Presence Detection
 *  ESP-IDF v5.x  |  ESP32-C3
 *  BLE Scan + Kalman Filter + HMAC Verify + WiFi + MQTT
 * ============================================================
 *
 *  Features:
 *  - BLE passive scan for beacon packets
 *  - HMAC-SHA256 payload verification (rejects fakes)
 *  - Per-beacon Kalman filter for RSSI smoothing
 *  - Room / Near / Far / No Signal classification
 *  - Publishes JSON to MQTT broker over WiFi
 *  - Tracks up to MAX_BEACONS simultaneously
 *  - Timeout detection (beacon out of range)
 *  - Status LED for WiFi / MQTT state
 *
 *  MQTT topics published:
 *    presence/node<NODE_ID>/beacon/<device_id>
 *    {"rssi_raw":-62,"rssi_filtered":-63.4,"state":"ROOM",
 *     "device_id":1,"hmac_ok":true,"ts":121,"node_id":1}
 *
 *  Usage:
 *  1. Set WIFI_SSID, WIFI_PASS, MQTT_BROKER_URI
 *  2. Set NODE_ID (unique per sensor node, e.g. 1=living room)
 *  3. Set SECRET_KEY (must match beacon firmware)
 *  4. idf.py set-target esp32c3 && idf.py build && idf.py flash
 * ============================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "driver/gpio.h"

#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"

#include "mbedtls/md.h"

#include "mqtt_client.h"

/* ============================================================
 *  CONFIGURATION — edit before flashing
 * ============================================================ */
#define WIFI_SSID           "Griya Raisya 2"          // WiFi network name
#define WIFI_PASS           "13raisya"      // WiFi password
#define MQTT_BROKER_URI     "mqtt://192.168.1.100:1883" // MQTT broker IP
#define NODE_ID             1                   // Unique ID for this sensor node
#define SECRET_KEY          "hackathon2026"     // Must match beacon firmware
#define COMPANY_ID          0x05AC              // Must match beacon firmware
#define PAYLOAD_MAGIC       0xBE                // Must match beacon firmware

#define RSSI_THRESHOLD_ROOM  (-65)              // dBm — stronger than this = ROOM
#define RSSI_THRESHOLD_NEAR  (-80)              // dBm — stronger than this = NEAR

#define SIGNAL_TIMEOUT_MS   5000               // ms — no packet = NO SIGNAL
#define MQTT_PUBLISH_MS     500                // ms — publish interval per beacon
#define MAX_BEACONS         8                  // max simultaneous beacons tracked
#define WIFI_RETRY_MAX      5                  // WiFi reconnect attempts

#define LED_GPIO            GPIO_NUM_8         // ESP32-C3 onboard LED
#define LED_ENABLED         1

/* ============================================================
 *  KALMAN FILTER TUNING
 *  Q: process noise  — higher = reacts faster to RSSI changes
 *  R: measurement noise — higher = smoother but slower response
 * ============================================================ */
#define KALMAN_Q            0.1f
#define KALMAN_R            2.0f

/* ============================================================
 *  INTERNAL CONSTANTS
 * ============================================================ */
#define TAG                 "SENSOR"
#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1
#define HMAC_TRUNCATE_BYTES 4
#define TOPIC_BUF_LEN       64
#define JSON_BUF_LEN        256

/* ============================================================
 *  BEACON PAYLOAD STRUCTURE (mirrors beacon_main.c)
 * ============================================================ */
typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  version;
    uint8_t  device_id;
    uint32_t timestamp;
    uint8_t  hmac[HMAC_TRUNCATE_BYTES];
} beacon_payload_t;

/* ============================================================
 *  KALMAN FILTER STATE
 * ============================================================ */
typedef struct {
    float x;   // current RSSI estimate
    float p;   // estimate uncertainty
    float q;   // process noise
    float r;   // measurement noise
} kalman_t;

static void kalman_init(kalman_t *k, float initial_rssi)
{
    k->x = initial_rssi;
    k->p = 1.0f;
    k->q = KALMAN_Q;
    k->r = KALMAN_R;
}

static float kalman_update(kalman_t *k, float measurement)
{
    k->p += k->q;
    float gain = k->p / (k->p + k->r);
    k->x += gain * (measurement - k->x);
    k->p *= (1.0f - gain);
    return k->x;
}

/* ============================================================
 *  BEACON TRACKING TABLE
 *  One entry per unique device_id seen.
 * ============================================================ */
typedef enum {
    STATE_NO_SIGNAL = 0,
    STATE_ROOM,
    STATE_NEAR,
    STATE_FAR,
} room_state_t;

static const char *state_str[] = {
    "NO_SIGNAL", "ROOM", "NEAR", "FAR"
};

typedef struct {
    bool      active;              // slot in use
    uint8_t   device_id;
    int       rssi_raw;            // last raw RSSI reading
    float     rssi_filtered;       // Kalman-smoothed RSSI
    room_state_t state;
    bool      hmac_ok;
    uint32_t  last_ts_beacon;      // timestamp from beacon payload
    int64_t   last_seen_us;        // esp_timer_get_time() of last packet
    uint32_t  packet_count;
    kalman_t  kalman;
    bool      needs_publish;       // flag: new data ready to send
} beacon_entry_t;

static beacon_entry_t s_beacons[MAX_BEACONS];
static SemaphoreHandle_t s_beacon_mutex = NULL;

/* ============================================================
 *  GLOBAL HANDLES
 * ============================================================ */
static EventGroupHandle_t  s_wifi_events   = NULL;
static esp_mqtt_client_handle_t s_mqtt     = NULL;
static bool                s_mqtt_connected = false;
static int                 s_wifi_retries  = 0;

/* ============================================================
 *  FORWARD DECLARATIONS
 * ============================================================ */
static bool         verify_hmac(uint8_t device_id, uint32_t timestamp,
                                 const uint8_t *rx_hmac);
static bool         parse_payload(const uint8_t *raw, uint8_t len,
                                   beacon_payload_t *out);
static beacon_entry_t *find_or_create_beacon(uint8_t device_id);
static room_state_t classify(float rssi);
static void         ble_gap_cb(esp_gap_ble_cb_event_t event,
                                esp_ble_gap_cb_param_t *param);
static void         wifi_event_cb(void *arg, esp_event_base_t base,
                                   int32_t id, void *data);
static void         mqtt_event_cb(void *arg, esp_event_base_t base,
                                   int32_t id, void *data);
static void         wifi_init(void);
static void         mqtt_init(void);
static void         ble_init(void);
static void         publish_task(void *arg);
static void         led_init(void);
static void         led_set(bool on);

/* ============================================================
 *  HMAC VERIFICATION
 *  Mirrors compute_hmac() in beacon_main.c exactly.
 * ============================================================ */
static bool verify_hmac(uint8_t device_id, uint32_t timestamp,
                         const uint8_t *rx_hmac)
{
    uint8_t input[5] = {
        device_id,
        (uint8_t)(timestamp       & 0xFF),
        (uint8_t)((timestamp >> 8)  & 0xFF),
        (uint8_t)((timestamp >> 16) & 0xFF),
        (uint8_t)((timestamp >> 24) & 0xFF),
    };

    uint8_t full_hmac[32];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx,
        (const unsigned char *)SECRET_KEY, strlen(SECRET_KEY));
    mbedtls_md_hmac_update(&ctx, input, sizeof(input));
    mbedtls_md_hmac_finish(&ctx, full_hmac);
    mbedtls_md_free(&ctx);

    /* Constant-time comparison — prevents timing attacks */
    uint8_t diff = 0;
    for (int i = 0; i < HMAC_TRUNCATE_BYTES; i++) {
        diff |= (full_hmac[i] ^ rx_hmac[i]);
    }
    return (diff == 0);
}

/* ============================================================
 *  PAYLOAD PARSER
 *  raw[] = manufacturer data bytes AFTER company ID stripped.
 *  Layout: [magic][version][device_id][ts 4B LE][hmac 4B]
 * ============================================================ */
static bool parse_payload(const uint8_t *raw, uint8_t len,
                            beacon_payload_t *out)
{
    if (len < 11) return false;
    if (raw[0] != PAYLOAD_MAGIC) return false;

    out->magic     = raw[0];
    out->version   = raw[1];
    out->device_id = raw[2];
    out->timestamp = (uint32_t)raw[3]
                   | ((uint32_t)raw[4] << 8)
                   | ((uint32_t)raw[5] << 16)
                   | ((uint32_t)raw[6] << 24);
    memcpy(out->hmac, &raw[7], HMAC_TRUNCATE_BYTES);
    return true;
}

/* ============================================================
 *  BEACON TABLE MANAGEMENT
 * ============================================================ */
static beacon_entry_t *find_or_create_beacon(uint8_t device_id)
{
    /* Find existing entry */
    for (int i = 0; i < MAX_BEACONS; i++) {
        if (s_beacons[i].active && s_beacons[i].device_id == device_id) {
            return &s_beacons[i];
        }
    }
    /* Allocate new slot */
    for (int i = 0; i < MAX_BEACONS; i++) {
        if (!s_beacons[i].active) {
            memset(&s_beacons[i], 0, sizeof(beacon_entry_t));
            s_beacons[i].active    = true;
            s_beacons[i].device_id = device_id;
            s_beacons[i].state     = STATE_NO_SIGNAL;
            kalman_init(&s_beacons[i].kalman, -70.0f);
            ESP_LOGI(TAG, "New beacon registered: device_id=0x%02X slot=%d",
                     device_id, i);
            return &s_beacons[i];
        }
    }
    ESP_LOGW(TAG, "Beacon table full — dropping device_id=0x%02X", device_id);
    return NULL;
}

static room_state_t classify(float rssi)
{
    if (rssi > RSSI_THRESHOLD_ROOM) return STATE_ROOM;
    if (rssi > RSSI_THRESHOLD_NEAR) return STATE_NEAR;
    return STATE_FAR;
}

/* ============================================================
 *  BLE GAP CALLBACK
 *  Called from the BLE stack for every advertisement received.
 *  Keep this fast — no blocking, no MQTT calls here.
 * ============================================================ */
static void ble_gap_cb(esp_gap_ble_cb_event_t event,
                        esp_ble_gap_cb_param_t *param)
{
    if (event != ESP_GAP_BLE_SCAN_RESULT_EVT) return;

    esp_ble_gap_cb_param_t *p = param;
    if (p->scan_rst.search_evt != ESP_GAP_SEARCH_INQ_RES_EVT) return;

    int rssi = p->scan_rst.rssi;
    if (rssi == 0 || rssi == 127) return;  // invalid RSSI values

    /* Walk AD structures to find manufacturer specific data (type 0xFF) */
    uint8_t *adv     = p->scan_rst.ble_adv;
    uint8_t  adv_len = p->scan_rst.adv_data_len;
    uint8_t  pos     = 0;

    while (pos + 1 < adv_len) {
        uint8_t ad_len  = adv[pos];
        if (ad_len == 0 || pos + ad_len >= adv_len) break;
        uint8_t ad_type = adv[pos + 1];

        if (ad_type == 0xFF && ad_len >= 3) {
            /* Extract company ID (little-endian 2 bytes after type) */
            uint16_t cid = (uint16_t)adv[pos + 2]
                         | ((uint16_t)adv[pos + 3] << 8);

            if (cid == COMPANY_ID) {
                /* Payload starts after [len][type][cid_lo][cid_hi] */
                const uint8_t *payload_raw = &adv[pos + 4];
                uint8_t payload_len = ad_len - 3; /* ad_len includes type+cid */

                beacon_payload_t pkt;
                if (!parse_payload(payload_raw, payload_len, &pkt)) {
                    ESP_LOGD(TAG, "Payload parse failed");
                    break;
                }

                bool hmac_valid = verify_hmac(pkt.device_id,
                                               pkt.timestamp,
                                               pkt.hmac);

                if (!hmac_valid) {
                    ESP_LOGW(TAG, "HMAC FAIL device=0x%02X ts=%lu — ignoring",
                             pkt.device_id, (unsigned long)pkt.timestamp);
                    break;
                }

                /* Update beacon table under mutex */
                if (xSemaphoreTake(s_beacon_mutex, pdMS_TO_TICKS(10))
                        == pdTRUE) {
                    beacon_entry_t *b = find_or_create_beacon(pkt.device_id);
                    if (b) {
                        b->rssi_raw      = rssi;
                        b->rssi_filtered = kalman_update(&b->kalman,
                                                          (float)rssi);
                        b->state         = classify(b->rssi_filtered);
                        b->hmac_ok       = hmac_valid;
                        b->last_ts_beacon = pkt.timestamp;
                        b->last_seen_us  = esp_timer_get_time();
                        b->packet_count++;
                        b->needs_publish = true;
                    }
                    xSemaphoreGive(s_beacon_mutex);
                }
                break;
            }
        }
        pos += ad_len + 1;
    }
}

/* ============================================================
 *  PUBLISH TASK
 *  Runs at MQTT_PUBLISH_MS interval.
 *  Checks each beacon — publishes if new data or timeout.
 * ============================================================ */
static void publish_task(void *arg)
{
    char topic[TOPIC_BUF_LEN];
    char json[JSON_BUF_LEN];
    int64_t now_us;
    int64_t timeout_us = (int64_t)SIGNAL_TIMEOUT_MS * 1000LL;

    ESP_LOGI(TAG, "Publish task started");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(MQTT_PUBLISH_MS));

        if (!s_mqtt_connected) continue;

        now_us = esp_timer_get_time();

        if (xSemaphoreTake(s_beacon_mutex, pdMS_TO_TICKS(20)) != pdTRUE) {
            continue;
        }

        for (int i = 0; i < MAX_BEACONS; i++) {
            beacon_entry_t *b = &s_beacons[i];
            if (!b->active) continue;

            /* Check for timeout */
            bool timed_out = (now_us - b->last_seen_us) > timeout_us;
            if (timed_out && b->state != STATE_NO_SIGNAL) {
                b->state        = STATE_NO_SIGNAL;
                b->needs_publish = true;
                ESP_LOGI(TAG, "Beacon 0x%02X timed out", b->device_id);
            }

            if (!b->needs_publish) continue;
            b->needs_publish = false;

            /* Build MQTT topic */
            snprintf(topic, sizeof(topic),
                     "presence/node%d/beacon/%d",
                     NODE_ID, b->device_id);

            /* Build JSON payload */
            snprintf(json, sizeof(json),
                "{\"node_id\":%d,"
                "\"device_id\":%d,"
                "\"rssi_raw\":%d,"
                "\"rssi_filtered\":%.1f,"
                "\"state\":\"%s\","
                "\"hmac_ok\":%s,"
                "\"beacon_ts\":%lu,"
                "\"timeout\":%s}",
                NODE_ID,
                b->device_id,
                b->rssi_raw,
                b->rssi_filtered,
                state_str[b->state],
                b->hmac_ok ? "true" : "false",
                (unsigned long)b->last_ts_beacon,
                timed_out   ? "true" : "false");

            esp_mqtt_client_publish(s_mqtt, topic, json, 0,
                                    1,    /* QoS 1 — at least once */
                                    0);   /* retain = 0 */

            ESP_LOGI(TAG, "Published [%s] %s", topic, json);
        }

        xSemaphoreGive(s_beacon_mutex);
    }
}

/* ============================================================
 *  WiFi
 * ============================================================ */
static void wifi_event_cb(void *arg, esp_event_base_t base,
                           int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();

    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_wifi_retries < WIFI_RETRY_MAX) {
            esp_wifi_connect();
            s_wifi_retries++;
            ESP_LOGW(TAG, "WiFi disconnected — retry %d/%d",
                     s_wifi_retries, WIFI_RETRY_MAX);
        } else {
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
            ESP_LOGE(TAG, "WiFi failed after %d retries", WIFI_RETRY_MAX);
        }
        led_set(false);

    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "WiFi connected — IP: " IPSTR,
                 IP2STR(&ev->ip_info.ip));
        s_wifi_retries = 0;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
        led_set(true);
    }
}

static void wifi_init(void)
{
    s_wifi_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_cb, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_cb, NULL));

    wifi_config_t wifi_cfg = {
        .sta = {
            .ssid     = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Waiting for WiFi...");
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_events,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE,
        pdMS_TO_TICKS(15000));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi ready");
    } else {
        ESP_LOGE(TAG, "WiFi connection failed — continuing without network");
    }
}

/* ============================================================
 *  MQTT
 * ============================================================ */
static void mqtt_event_cb(void *arg, esp_event_base_t base,
                           int32_t id, void *data)
{
    esp_mqtt_event_handle_t ev = (esp_mqtt_event_handle_t)data;
    switch ((esp_mqtt_event_id_t)id) {
        case MQTT_EVENT_CONNECTED:
            s_mqtt_connected = true;
            ESP_LOGI(TAG, "MQTT connected");
            break;
        case MQTT_EVENT_DISCONNECTED:
            s_mqtt_connected = false;
            ESP_LOGW(TAG, "MQTT disconnected — will reconnect automatically");
            break;
        case MQTT_EVENT_ERROR:
            ESP_LOGE(TAG, "MQTT error");
            break;
        default:
            break;
    }
}

static void mqtt_init(void)
{
    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = MQTT_BROKER_URI,
    };
    s_mqtt = esp_mqtt_client_init(&cfg);
    esp_mqtt_client_register_event(s_mqtt, ESP_EVENT_ANY_ID,
                                    mqtt_event_cb, NULL);
    esp_mqtt_client_start(s_mqtt);
    ESP_LOGI(TAG, "MQTT client started → %s", MQTT_BROKER_URI);
}

/* ============================================================
 *  BLE INIT
 *  ESP32-C3: only BLE (no Classic BT), use ESP_BT_MODE_BLE only.
 * ============================================================ */
static void ble_init(void)
{
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());
    ESP_ERROR_CHECK(esp_ble_gap_register_callback(ble_gap_cb));

    /* Passive scan — do not send scan requests, saves power */
    esp_ble_scan_params_t scan_params = {
        .scan_type          = BLE_SCAN_TYPE_PASSIVE,
        .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
        .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
        .scan_interval      = 0x50,   /* 50 ms — (0x50 * 0.625) */
        .scan_window        = 0x30,   /* 30 ms active window */
        .scan_duplicate     = BLE_SCAN_DUPLICATE_DISABLE,
    };
    ESP_ERROR_CHECK(esp_ble_gap_set_scan_params(&scan_params));
    ESP_ERROR_CHECK(esp_ble_gap_start_scanning(0)); /* 0 = scan forever */
    ESP_LOGI(TAG, "BLE scanning started");
}

/* ============================================================
 *  LED HELPERS
 * ============================================================ */
static void led_init(void)
{
#if LED_ENABLED
    gpio_config_t cfg = {
        .pin_bit_mask = (1ULL << LED_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
    gpio_set_level(LED_GPIO, 0);
#endif
}

static void led_set(bool on)
{
#if LED_ENABLED
    gpio_set_level(LED_GPIO, on ? 1 : 0);
#endif
}

/* ============================================================
 *  app_main
 * ============================================================ */
void app_main(void)
{
    ESP_LOGI(TAG, "=== Sensor Node Firmware v1.0 ===");
    ESP_LOGI(TAG, "Node ID  : %d", NODE_ID);
    ESP_LOGI(TAG, "Broker   : %s", MQTT_BROKER_URI);
    ESP_LOGI(TAG, "Thresholds: ROOM>%d dBm  NEAR>%d dBm",
             RSSI_THRESHOLD_ROOM, RSSI_THRESHOLD_NEAR);

    /* NVS — required by WiFi and BLE stacks */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* LED */
    led_init();

    /* Beacon tracking mutex */
    s_beacon_mutex = xSemaphoreCreateMutex();
    configASSERT(s_beacon_mutex != NULL);

    /* Clear beacon table */
    memset(s_beacons, 0, sizeof(s_beacons));

    /* WiFi — must come before MQTT */
    wifi_init();

    /* MQTT */
    mqtt_init();

    /* BLE — start scanning */
    ble_init();

    /* Publish task — reads beacon table, sends to MQTT broker */
    xTaskCreate(publish_task, "publish_task",
                4096,    /* stack size in bytes */
                NULL,
                5,       /* priority */
                NULL);

    /* ============================================================
     *  Main loop — periodic status log only
     *  All real work happens in ble_gap_cb and publish_task.
     * ============================================================ */
    uint32_t count = 0;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        count++;

        ESP_LOGI(TAG, "--- Status [%lu] WiFi:%s MQTT:%s ---",
                 (unsigned long)count,
                 (s_wifi_retries < WIFI_RETRY_MAX) ? "UP" : "DOWN",
                 s_mqtt_connected ? "UP" : "DOWN");

        if (xSemaphoreTake(s_beacon_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
            for (int i = 0; i < MAX_BEACONS; i++) {
                beacon_entry_t *b = &s_beacons[i];
                if (!b->active) continue;
                ESP_LOGI(TAG,
                    "  beacon 0x%02X  raw=%d dBm  filtered=%.1f dBm"
                    "  state=%s  pkts=%lu",
                    b->device_id,
                    b->rssi_raw,
                    b->rssi_filtered,
                    state_str[b->state],
                    (unsigned long)b->packet_count);
            }
            xSemaphoreGive(s_beacon_mutex);
        }
    }
}