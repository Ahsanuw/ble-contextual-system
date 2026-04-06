/*
 * ============================================================
 *  CONTROLLER FIRMWARE — Energy-Efficient Presence Detection
 *  ESP-IDF v5.x  |  ESP32
 *
 *  Responsibilities:
 *  - Subscribe to all sensor node MQTT topics
 *  - Compare RSSI across all rooms
 *  - Determine active room (highest filtered RSSI)
 *  - Drive GPIO relays (light + AC per room)
 *  - Serve a live web dashboard over HTTP
 *  - Track energy savings (kWh, Rupiah, CO2)
 *
 *  MQTT topics consumed:
 *    presence/node+/beacon/+
 *    Payload: {"node_id":1,"device_id":1,"rssi_filtered":-63.4,
 *              "state":"ROOM","hmac_ok":true,"timeout":false}
 *
 *  Web dashboard:
 *    http://<controller-ip>/          — live room status page
 *    http://<controller-ip>/api/state — JSON API for JS polling
 *
 *  Relay wiring (active HIGH):
 *    RELAY_ROOM1_LIGHT → GPIO 18
 *    RELAY_ROOM1_AC    → GPIO 19
 *    RELAY_ROOM2_LIGHT → GPIO 21
 *    RELAY_ROOM2_AC    → GPIO 22
 *    RELAY_ROOM3_LIGHT → GPIO 23
 *    RELAY_ROOM3_AC    → GPIO 25
 *
 *  Usage:
 *  1. Set WIFI_SSID, WIFI_PASS, MQTT_BROKER_URI
 *  2. Set NUM_ROOMS to match number of sensor nodes
 *  3. Set relay GPIO pins per room
 *  4. idf.py set-target esp32 && idf.py build && idf.py flash
 * ============================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
#include "esp_http_server.h"
#include "driver/gpio.h"
#include "cJSON.h"

#include "mqtt_client.h"

/* ============================================================
 *  CONFIGURATION — edit before flashing
 * ============================================================ */
#define WIFI_SSID           "YourSSID"
#define WIFI_PASS           "YourPassword"
#define MQTT_BROKER_URI     "mqtt://192.168.1.100:1883"

#define NUM_ROOMS           3       /* number of sensor nodes / rooms */
#define SIGNAL_TIMEOUT_MS   8000    /* ms — room inactive after this */
#define HYSTERESIS_DBM      5.0f    /* dBm — must exceed current room
                                       by this much to switch rooms */
#define RELAY_ACTIVE_HIGH   1       /* 1 = relay ON when GPIO HIGH
                                       0 = relay ON when GPIO LOW (inverted) */

/* Power consumption constants for energy tracking */
#define AC_POWER_WATT       900.0f  /* 1 PK AC unit */
#define LAMP_POWER_WATT     20.0f   /* LED lamp per room */
#define PLN_RATE_PER_KWH    1444.0f /* IDR — PLN electricity rate */
#define CO2_GRAM_PER_KWH    785.0f  /* Indonesia grid emission factor */

#define WIFI_RETRY_MAX      5
#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1

#define TAG                 "CONTROLLER"
#define HTTP_PORT           80
#define JSON_API_BUF        2048
#define HTML_CHUNK          1024

/* ============================================================
 *  RELAY GPIO MAP
 *  Index 0 = node_id 1 (room 1), index 1 = node_id 2, etc.
 *  Set to GPIO_NUM_NC (-1) if relay not connected.
 * ============================================================ */
static const gpio_num_t RELAY_LIGHT[NUM_ROOMS] = {
    GPIO_NUM_18,   /* room 1 light */
    GPIO_NUM_21,   /* room 2 light */
    GPIO_NUM_23,   /* room 3 light */
};

static const gpio_num_t RELAY_AC[NUM_ROOMS] = {
    GPIO_NUM_19,   /* room 1 AC */
    GPIO_NUM_22,   /* room 2 AC */
    GPIO_NUM_25,   /* room 3 AC */
};

static const char *ROOM_NAME[NUM_ROOMS] = {
    "Living Room",
    "Bedroom",
    "Kitchen",
};

/* ============================================================
 *  ROOM STATE
 * ============================================================ */
typedef struct {
    int     node_id;
    float   rssi_filtered;
    char    state[16];        /* "ROOM", "NEAR", "FAR", "NO_SIGNAL" */
    bool    hmac_ok;
    bool    timeout;
    int64_t last_update_us;   /* esp_timer_get_time() */
    bool    relay_light_on;
    bool    relay_ac_on;
    uint8_t device_id;        /* which beacon is being tracked */
} room_state_t;

static room_state_t s_rooms[NUM_ROOMS];
static int          s_active_room   = -1;  /* index into s_rooms, -1 = none */
static int          s_prev_active   = -1;
static SemaphoreHandle_t s_state_mutex = NULL;

/* ============================================================
 *  ENERGY TRACKING
 * ============================================================ */
typedef struct {
    int64_t  session_start_us;    /* when system started */
    float    kwh_saved;
    float    rupiah_saved;
    float    co2_saved_gram;
    uint32_t room_switches;       /* how many times active room changed */
} energy_t;

static energy_t s_energy = {0};

/* ============================================================
 *  GLOBAL HANDLES
 * ============================================================ */
static EventGroupHandle_t       s_wifi_events    = NULL;
static esp_mqtt_client_handle_t s_mqtt           = NULL;
static bool                     s_mqtt_connected = false;
static int                      s_wifi_retries   = 0;
static httpd_handle_t           s_httpd          = NULL;

/* ============================================================
 *  FORWARD DECLARATIONS
 * ============================================================ */
static void     relay_init(void);
static void     relay_set_room(int room_idx, bool on);
static void     relay_all_off(void);
static int      find_active_room(void);
static void     apply_relay_state(int new_active);
static void     update_energy(int prev_active, int new_active);
static void     parse_mqtt_message(const char *topic, int topic_len,
                                    const char *data,  int data_len);
static void     wifi_event_cb(void *arg, esp_event_base_t base,
                               int32_t id, void *data);
static void     mqtt_event_cb(void *arg, esp_event_base_t base,
                               int32_t id, void *data);
static void     wifi_init(void);
static void     mqtt_init(void);
static void     http_init(void);
static void     controller_task(void *arg);
static esp_err_t http_handler_root(httpd_req_t *req);
static esp_err_t http_handler_api(httpd_req_t *req);

/* ============================================================
 *  RELAY CONTROL
 * ============================================================ */
static void relay_init(void)
{
    gpio_config_t cfg = {
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };

    for (int i = 0; i < NUM_ROOMS; i++) {
        if (RELAY_LIGHT[i] != GPIO_NUM_NC) {
            cfg.pin_bit_mask = (1ULL << RELAY_LIGHT[i]);
            gpio_config(&cfg);
        }
        if (RELAY_AC[i] != GPIO_NUM_NC) {
            cfg.pin_bit_mask = (1ULL << RELAY_AC[i]);
            gpio_config(&cfg);
        }
    }

    relay_all_off();
    ESP_LOGI(TAG, "Relays initialized — all OFF");
}

/* Turn light + AC relay ON or OFF for a given room index */
static void relay_set_room(int room_idx, bool on)
{
    if (room_idx < 0 || room_idx >= NUM_ROOMS) return;

    int level = on ? (RELAY_ACTIVE_HIGH ? 1 : 0)
                   : (RELAY_ACTIVE_HIGH ? 0 : 1);

    if (RELAY_LIGHT[room_idx] != GPIO_NUM_NC) {
        gpio_set_level(RELAY_LIGHT[room_idx], level);
    }
    if (RELAY_AC[room_idx] != GPIO_NUM_NC) {
        gpio_set_level(RELAY_AC[room_idx], level);
    }

    s_rooms[room_idx].relay_light_on = on;
    s_rooms[room_idx].relay_ac_on    = on;

    ESP_LOGI(TAG, "Relay [%s] → %s",
             ROOM_NAME[room_idx], on ? "ON" : "OFF");
}

static void relay_all_off(void)
{
    for (int i = 0; i < NUM_ROOMS; i++) {
        relay_set_room(i, false);
    }
}

/* ============================================================
 *  ROOM CLASSIFICATION & ACTIVE ROOM SELECTION
 *
 *  Algorithm:
 *  1. Discard rooms with timeout or NO_SIGNAL state
 *  2. Among valid rooms, find highest rssi_filtered
 *  3. Apply hysteresis: only switch if new room exceeds
 *     current active room's RSSI by HYSTERESIS_DBM
 *     (prevents rapid flickering at room boundaries)
 * ============================================================ */
static int find_active_room(void)
{
    int64_t now      = esp_timer_get_time();
    int64_t timeout  = (int64_t)SIGNAL_TIMEOUT_MS * 1000LL;

    int   best_idx  = -1;
    float best_rssi = -200.0f;  /* start below any real RSSI */

    for (int i = 0; i < NUM_ROOMS; i++) {
        /* Skip rooms with no recent data */
        if (s_rooms[i].last_update_us == 0) continue;
        if ((now - s_rooms[i].last_update_us) > timeout) continue;
        if (strcmp(s_rooms[i].state, "NO_SIGNAL") == 0) continue;
        if (strcmp(s_rooms[i].state, "FAR") == 0) continue;
        if (!s_rooms[i].hmac_ok) continue;  /* reject unverified beacons */

        if (s_rooms[i].rssi_filtered > best_rssi) {
            best_rssi = s_rooms[i].rssi_filtered;
            best_idx  = i;
        }
    }

    if (best_idx == -1) return -1;  /* nobody home */

    /* Apply hysteresis — only switch if significantly stronger */
    if (s_active_room != -1 && s_active_room != best_idx) {
        float current_rssi = s_rooms[s_active_room].rssi_filtered;
        if ((best_rssi - current_rssi) < HYSTERESIS_DBM) {
            return s_active_room;  /* stay in current room */
        }
    }

    return best_idx;
}

/* Apply relay changes based on new active room */
static void apply_relay_state(int new_active)
{
    if (new_active == s_active_room) return;  /* no change */

    ESP_LOGI(TAG, "Active room: %s → %s",
             s_active_room == -1 ? "NONE" : ROOM_NAME[s_active_room],
             new_active    == -1 ? "NONE" : ROOM_NAME[new_active]);

    /* Turn OFF previous room */
    if (s_active_room != -1) {
        relay_set_room(s_active_room, false);
    }

    /* Turn ON new room */
    if (new_active != -1) {
        relay_set_room(new_active, true);
    } else {
        /* Nobody home — all off already handled above */
        ESP_LOGI(TAG, "No active room — all devices OFF");
    }

    update_energy(s_active_room, new_active);
    s_active_room = new_active;
    s_energy.room_switches++;
}

/* ============================================================
 *  ENERGY SAVINGS CALCULATION
 *
 *  Logic:
 *  When active room changes, the IDLE rooms are powered OFF.
 *  We accumulate saved energy = (NUM_ROOMS - 1) rooms OFF
 *  for the duration they were idle.
 *
 *  This is a simplified model — real savings depend on actual
 *  baseline (were those rooms going to be ON anyway?).
 *  For demo purposes, we assume all rooms would be ON without
 *  this system, so savings = (inactive rooms) * power * time.
 * ============================================================ */
static void update_energy(int prev_active, int new_active)
{
    /* Nothing to calculate if no previous active room */
    if (prev_active == -1) return;

    /* Time the previous state was held (seconds) */
    static int64_t last_switch_us = 0;
    int64_t now = esp_timer_get_time();

    if (last_switch_us == 0) {
        last_switch_us = s_energy.session_start_us;
    }

    float elapsed_sec = (float)(now - last_switch_us) / 1e6f;
    last_switch_us = now;

    /* Rooms that were OFF (all except prev_active) */
    int idle_rooms = NUM_ROOMS - 1;
    float power_per_room = AC_POWER_WATT + LAMP_POWER_WATT;  /* watts */
    float saved_wh  = idle_rooms * power_per_room * (elapsed_sec / 3600.0f);
    float saved_kwh = saved_wh / 1000.0f;

    s_energy.kwh_saved      += saved_kwh;
    s_energy.rupiah_saved   += saved_kwh * PLN_RATE_PER_KWH;
    s_energy.co2_saved_gram += saved_kwh * CO2_GRAM_PER_KWH;

    ESP_LOGI(TAG, "Energy saved: +%.4f kWh | Total: %.3f kWh / Rp %.0f / %.1f g CO2",
             saved_kwh,
             s_energy.kwh_saved,
             s_energy.rupiah_saved,
             s_energy.co2_saved_gram);
}

/* ============================================================
 *  MQTT MESSAGE PARSER
 *
 *  Topic format: presence/node{N}/beacon/{id}
 *  We extract node_id from topic, then parse JSON payload.
 * ============================================================ */
static void parse_mqtt_message(const char *topic, int topic_len,
                                const char *data,  int data_len)
{
    /* Parse node_id from topic: presence/node{N}/beacon/{id} */
    int node_id = -1;
    /* Find "node" in topic, read integer after it */
    const char *p = strstr(topic, "node");
    if (p) {
        node_id = atoi(p + 4);  /* skip "node" */
    }

    if (node_id < 1 || node_id > NUM_ROOMS) {
        ESP_LOGD(TAG, "Unknown node_id=%d in topic", node_id);
        return;
    }

    int room_idx = node_id - 1;  /* convert to 0-based index */

    /* Parse JSON payload */
    char *json_str = strndup(data, data_len);
    if (!json_str) return;

    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) {
        ESP_LOGW(TAG, "Failed to parse JSON from node %d", node_id);
        return;
    }

    /* Extract fields */
    cJSON *j_rssi    = cJSON_GetObjectItem(root, "rssi_filtered");
    cJSON *j_state   = cJSON_GetObjectItem(root, "state");
    cJSON *j_hmac    = cJSON_GetObjectItem(root, "hmac_ok");
    cJSON *j_timeout = cJSON_GetObjectItem(root, "timeout");
    cJSON *j_devid   = cJSON_GetObjectItem(root, "device_id");

    if (!j_rssi || !j_state) {
        ESP_LOGW(TAG, "Missing required fields in JSON");
        cJSON_Delete(root);
        return;
    }

    /* Update room state under mutex */
    if (xSemaphoreTake(s_state_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
        s_rooms[room_idx].node_id       = node_id;
        s_rooms[room_idx].rssi_filtered = (float)j_rssi->valuedouble;
        s_rooms[room_idx].hmac_ok       = j_hmac  ? j_hmac->valueint  : false;
        s_rooms[room_idx].timeout       = j_timeout? j_timeout->valueint: false;
        s_rooms[room_idx].device_id     = j_devid  ? j_devid->valueint : 0;
        s_rooms[room_idx].last_update_us = esp_timer_get_time();
        strncpy(s_rooms[room_idx].state,
                j_state->valuestring,
                sizeof(s_rooms[room_idx].state) - 1);
        xSemaphoreGive(s_state_mutex);
    }

    cJSON_Delete(root);

    ESP_LOGD(TAG, "Room [%s] rssi=%.1f state=%s hmac=%s",
             ROOM_NAME[room_idx],
             s_rooms[room_idx].rssi_filtered,
             s_rooms[room_idx].state,
             s_rooms[room_idx].hmac_ok ? "OK" : "FAIL");
}

/* ============================================================
 *  CONTROLLER TASK
 *  Runs every 500ms — re-evaluates active room and drives relays.
 * ============================================================ */
static void controller_task(void *arg)
{
    ESP_LOGI(TAG, "Controller task started");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(500));

        if (xSemaphoreTake(s_state_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
            int new_active = find_active_room();
            apply_relay_state(new_active);
            xSemaphoreGive(s_state_mutex);
        }
    }
}

/* ============================================================
 *  WEB DASHBOARD — HTML PAGE
 *
 *  Served at GET /
 *  Self-refreshing via JavaScript polling /api/state every 1s.
 *  No external CDN dependencies — works offline on local network.
 * ============================================================ */

/*
 * ESP-IDF embeds dashboard.html at build time via EMBED_FILES
 * in main/CMakeLists.txt. The linker exposes these symbols:
 *
 *   _binary_dashboard_html_start  — pointer to first byte
 *   _binary_dashboard_html_end    — pointer one past last byte
 *
 * File length = end - start (no null terminator added).
 */
extern const uint8_t dashboard_html_start[] asm("_binary_dashboard_html_start");
extern const uint8_t dashboard_html_end[]   asm("_binary_dashboard_html_end");

static esp_err_t http_handler_root(httpd_req_t *req)
{
    size_t html_len = dashboard_html_end - dashboard_html_start;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char *)dashboard_html_start, html_len);
    return ESP_OK;
}

/* ============================================================
 *  WEB DASHBOARD — JSON API
 *  GET /api/state
 *  Returns full system state as JSON, polled by dashboard JS.
 * ============================================================ */
static esp_err_t http_handler_api(httpd_req_t *req)
{
    char *buf = malloc(JSON_API_BUF);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    int64_t now = esp_timer_get_time();

    if (xSemaphoreTake(s_state_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        free(buf);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    /* Build JSON manually for speed (no cJSON allocation overhead) */
    int pos = 0;
    pos += snprintf(buf + pos, JSON_API_BUF - pos,
        "{\"active_room\":%d,"
        "\"energy\":{"
          "\"kwh_saved\":%.4f,"
          "\"rupiah_saved\":%.0f,"
          "\"co2_gram\":%.1f,"
          "\"room_switches\":%lu"
        "},"
        "\"mqtt\":%s,"
        "\"rooms\":[",
        s_active_room,
        s_energy.kwh_saved,
        s_energy.rupiah_saved,
        s_energy.co2_saved_gram,
        (unsigned long)s_energy.room_switches,
        s_mqtt_connected ? "true" : "false");

    for (int i = 0; i < NUM_ROOMS; i++) {
        int64_t age_ms = (now - s_rooms[i].last_update_us) / 1000LL;
        bool    stale  = (s_rooms[i].last_update_us == 0) ||
                         (age_ms > SIGNAL_TIMEOUT_MS);

        pos += snprintf(buf + pos, JSON_API_BUF - pos,
            "%s{"
              "\"name\":\"%s\","
              "\"node_id\":%d,"
              "\"rssi\":%.1f,"
              "\"state\":\"%s\","
              "\"active\":%s,"
              "\"light\":%s,"
              "\"ac\":%s,"
              "\"hmac\":%s,"
              "\"age_ms\":%lld,"
              "\"stale\":%s"
            "}",
            i > 0 ? "," : "",
            ROOM_NAME[i],
            s_rooms[i].node_id,
            stale ? -120.0f : s_rooms[i].rssi_filtered,
            stale ? "NO_SIGNAL" : s_rooms[i].state,
            (s_active_room == i) ? "true" : "false",
            s_rooms[i].relay_light_on ? "true" : "false",
            s_rooms[i].relay_ac_on    ? "true" : "false",
            s_rooms[i].hmac_ok        ? "true" : "false",
            (long long)age_ms,
            stale ? "true" : "false");
    }

    pos += snprintf(buf + pos, JSON_API_BUF - pos, "]}");

    xSemaphoreGive(s_state_mutex);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_send(req, buf, pos);
    free(buf);
    return ESP_OK;
}

/* ============================================================
 *  HTTP SERVER
 * ============================================================ */
static void http_init(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = HTTP_PORT;
    cfg.max_open_sockets = 4;

    if (httpd_start(&s_httpd, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return;
    }

    httpd_uri_t uri_root = {
        .uri     = "/",
        .method  = HTTP_GET,
        .handler = http_handler_root,
    };
    httpd_uri_t uri_api = {
        .uri     = "/api/state",
        .method  = HTTP_GET,
        .handler = http_handler_api,
    };

    httpd_register_uri_handler(s_httpd, &uri_root);
    httpd_register_uri_handler(s_httpd, &uri_api);

    ESP_LOGI(TAG, "HTTP server started on port %d", HTTP_PORT);
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
            ESP_LOGI(TAG, "MQTT connected — subscribing to presence/#");
            /* Subscribe to all sensor node topics */
            esp_mqtt_client_subscribe(s_mqtt, "presence/#", 1);
            break;

        case MQTT_EVENT_DISCONNECTED:
            s_mqtt_connected = false;
            ESP_LOGW(TAG, "MQTT disconnected");
            break;

        case MQTT_EVENT_DATA:
            /* Forward to parser — ev->topic/data are NOT null-terminated */
            parse_mqtt_message(ev->topic,    ev->topic_len,
                               ev->data,     ev->data_len);
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
            ESP_LOGW(TAG, "WiFi retry %d/%d", s_wifi_retries, WIFI_RETRY_MAX);
        } else {
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
        }

    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "WiFi connected — IP: " IPSTR " — open http://" IPSTR,
                 IP2STR(&ev->ip_info.ip), IP2STR(&ev->ip_info.ip));
        s_wifi_retries = 0;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
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
    xEventGroupWaitBits(s_wifi_events,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(15000));
}

/* ============================================================
 *  app_main
 * ============================================================ */
void app_main(void)
{
    ESP_LOGI(TAG, "=== Controller Firmware v1.0 ===");
    ESP_LOGI(TAG, "Rooms    : %d", NUM_ROOMS);
    ESP_LOGI(TAG, "Broker   : %s", MQTT_BROKER_URI);
    ESP_LOGI(TAG, "Hysteresis: %.0f dBm", HYSTERESIS_DBM);

    /* NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Mutex + state */
    s_state_mutex = xSemaphoreCreateMutex();
    configASSERT(s_state_mutex != NULL);
    memset(s_rooms,  0, sizeof(s_rooms));
    memset(&s_energy, 0, sizeof(s_energy));
    s_energy.session_start_us = esp_timer_get_time();

    /* Relays — all OFF at boot */
    relay_init();

    /* WiFi → MQTT → HTTP */
    wifi_init();
    mqtt_init();
    http_init();

    /* Controller decision loop */
    xTaskCreate(controller_task, "ctrl_task", 4096, NULL, 5, NULL);

    /* Main loop — status log every 10s */
    uint32_t count = 0;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        count++;
        ESP_LOGI(TAG,
            "[%lu] Active room: %s | kWh saved: %.3f | Switches: %lu",
            (unsigned long)count,
            s_active_room == -1 ? "NONE" : ROOM_NAME[s_active_room],
            s_energy.kwh_saved,
            (unsigned long)s_energy.room_switches);
    }
}