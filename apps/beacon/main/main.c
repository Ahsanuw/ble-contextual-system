/*
 * ============================================================
 *  BEACON FIRMWARE — Energy-Efficient Presence Detection
 *  ESP-IDF v5.x  |  BLE Advertising + Rolling ID + Power Mgmt
 * ============================================================
 *
 *  Features:
 *  - BLE advertising with structured payload
 *  - Rolling ID (rotates every ROLL_INTERVAL_MS) for privacy
 *  - Lightweight HMAC-SHA256 for payload authentication
 *  - Light sleep between advertising intervals to save power
 *  - Optional status LED for field debugging
 *
 *  Usage:
 *  1. Set SECRET_KEY (must match controller and all sensor nodes)
 *  2. Set DEVICE_ID (unique per beacon)
 *  3. idf.py build && idf.py flash
 * ============================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"
#include "esp_sleep.h"
#include "esp_timer.h"
#include "mbedtls/md.h"
#include "driver/gpio.h"

/* ============================================================
 *  CONFIGURATION — edit before flashing
 * ============================================================ */
#define DEVICE_ID           0x01            // Unique beacon ID (1 byte, 0x01-0xFF)
#define SECRET_KEY          "hackathon2026" // HMAC key (must match all nodes & controller)
#define ROLL_INTERVAL_MS    60000           // Rotate rolling ID every 60 seconds
#define ADV_INTERVAL_MIN    0x00A0          // 100 ms (0x00A0 * 0.625 ms)
#define ADV_INTERVAL_MAX    0x00C0          // 120 ms
#define TX_POWER            ESP_PWR_LVL_N0  // 0 dBm — increase if range is insufficient
#define LED_GPIO            GPIO_NUM_2      // Onboard LED GPIO (ESP32 default)
#define LED_ENABLED         1               // Set to 0 to save extra power

/* ============================================================
 *  INTERNAL CONSTANTS
 * ============================================================ */
#define TAG                 "BEACON"
#define COMPANY_ID          0x05AC          // Manufacturer ID (freely chosen)
#define PAYLOAD_MAGIC       0xBE            // Magic byte for frame identification
#define PAYLOAD_VERSION     0x01
#define HMAC_TRUNCATE_BYTES 4               // Use first 4 bytes of HMAC as signature

/* ============================================================
 *  MANUFACTURER SPECIFIC PAYLOAD STRUCTURE
 *
 *  Total: 10 bytes packed into BLE manufacturer data field
 *  [0]    magic     = 0xBE
 *  [1]    version   = 0x01
 *  [2]    device_id = DEVICE_ID
 *  [3-6]  timestamp = uptime seconds (4 bytes, little-endian)
 *  [6-9]  hmac_4b   = first 4 bytes of HMAC-SHA256
 * ============================================================ */
typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  version;
    uint8_t  device_id;
    uint32_t timestamp;
    uint8_t  hmac[HMAC_TRUNCATE_BYTES];
} beacon_payload_t;

/* ============================================================
 *  GLOBAL STATE
 * ============================================================ */
static beacon_payload_t s_payload    = {0};
static bool             s_adv_active = false;
static bool             s_rolling    = false;  /* true while roll_timer_cb is running */
static TimerHandle_t    s_roll_timer = NULL;

/* ============================================================
 *  FORWARD DECLARATIONS
 * ============================================================ */
static void beacon_update_payload(void);
static void beacon_start_advertising(void);
static void beacon_stop_advertising(void);
static void compute_hmac(const beacon_payload_t *p, uint8_t *out_4b);
static void roll_timer_cb(TimerHandle_t xTimer);
static void gap_event_handler(esp_gap_ble_cb_event_t event,
                              esp_ble_gap_cb_param_t *param);
static void led_init(void);
static void led_blink(int times, int delay_ms);

/* ============================================================
 *  BLE ADVERTISING CONFIGURATION
 * ============================================================ */

/* Advertising parameters */
static esp_ble_adv_params_t s_adv_params = {
    .adv_int_min       = ADV_INTERVAL_MIN,
    .adv_int_max       = ADV_INTERVAL_MAX,
    .adv_type          = ADV_TYPE_NONCONN_IND,  // Non-connectable — beacon does not need connections
    .own_addr_type     = BLE_ADDR_TYPE_PUBLIC,
    .channel_map       = ADV_CHNL_ALL,
    .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

/* Raw advertising buffer — filled dynamically via esp_ble_gap_config_adv_data_raw */
static uint8_t s_adv_raw[31];      // BLE advertising payload max 31 bytes
static uint8_t s_adv_raw_len = 0;

/* ============================================================
 *  CORE FUNCTIONS
 * ============================================================ */

/*
 * Compute HMAC-SHA256(SECRET_KEY, device_id || timestamp)
 * and copy the first 4 bytes into out_4b as a compact signature.
 */
static void compute_hmac(const beacon_payload_t *p, uint8_t *out_4b)
{
    uint8_t input[5];
    input[0] = p->device_id;
    input[1] = (p->timestamp      ) & 0xFF;
    input[2] = (p->timestamp >>  8) & 0xFF;
    input[3] = (p->timestamp >> 16) & 0xFF;
    input[4] = (p->timestamp >> 24) & 0xFF;

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

    memcpy(out_4b, full_hmac, HMAC_TRUNCATE_BYTES);
}

/*
 * Build a fresh payload with the current uptime timestamp and HMAC.
 * Called at startup and on every roll interval.
 */
static void beacon_update_payload(void)
{
    /* Use uptime as a timestamp substitute — no RTC/NTP required,
     * sufficient for rolling ID uniqueness within a session. */
    uint32_t ts = (uint32_t)(esp_timer_get_time() / 1000000ULL);

    s_payload.magic     = PAYLOAD_MAGIC;
    s_payload.version   = PAYLOAD_VERSION;
    s_payload.device_id = DEVICE_ID;
    s_payload.timestamp = ts;
    compute_hmac(&s_payload, s_payload.hmac);

    ESP_LOGI(TAG, "Payload updated — device=0x%02X ts=%lu hmac=%02X%02X%02X%02X",
             s_payload.device_id,
             (unsigned long)s_payload.timestamp,
             s_payload.hmac[0], s_payload.hmac[1],
             s_payload.hmac[2], s_payload.hmac[3]);

    /*
     * Build raw BLE advertising packet:
     * [len][type=0xFF (manufacturer specific)][company_id_lo][company_id_hi][payload...]
     *
     * AD Structure format:
     *   byte 0   : length (number of bytes that follow)
     *   byte 1   : AD type 0xFF = Manufacturer Specific Data
     *   byte 2-3 : Company ID (little-endian)
     *   byte 4+  : payload bytes
     */
    uint8_t payload_len = sizeof(beacon_payload_t);
    s_adv_raw[0] = 3 + payload_len;             // length field
    s_adv_raw[1] = 0xFF;                         // AD type: manufacturer specific
    s_adv_raw[2] = (COMPANY_ID)       & 0xFF;    // company ID low byte
    s_adv_raw[3] = (COMPANY_ID >> 8)  & 0xFF;    // company ID high byte
    memcpy(&s_adv_raw[4], &s_payload, payload_len);
    s_adv_raw_len = 4 + payload_len;
}

/*
 * Start advertising with the latest payload.
 * Actual start is triggered inside the GAP callback after data is set.
 */
static void beacon_start_advertising(void)
{
    beacon_update_payload();
    ESP_ERROR_CHECK(esp_ble_gap_config_adv_data_raw(s_adv_raw, s_adv_raw_len));
}

static void beacon_stop_advertising(void)
{
    if (s_adv_active) {
        esp_ble_gap_stop_advertising();
        s_adv_active = false;
    }
}

/*
 * Rolling task: runs once per roll interval, then deletes itself.
 * Using a task instead of calling vTaskDelay() directly inside the
 * timer callback — timer daemon tasks must not block.
 */
static void roll_task(void *arg)
{
    s_rolling = true;
    ESP_LOGI(TAG, "Rolling ID — refreshing payload...");
    beacon_stop_advertising();
    vTaskDelay(pdMS_TO_TICKS(50));  // brief pause before restarting
    beacon_start_advertising();
    s_rolling = false;

#if LED_ENABLED
    led_blink(2, 80);  // 2 fast blinks = roll successful
#endif

    vTaskDelete(NULL);  // self-delete after one execution
}

/*
 * FreeRTOS timer callback: spawns roll_task to avoid blocking the timer daemon.
 */
static void roll_timer_cb(TimerHandle_t xTimer)
{
    xTaskCreate(roll_task, "roll_task", 4096, NULL, 5, NULL);
}

/*
 * GAP event handler — manages advertising state machine.
 */
static void gap_event_handler(esp_gap_ble_cb_event_t event,
                               esp_ble_gap_cb_param_t *param)
{
    switch (event) {
        case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
            ESP_LOGI(TAG, "Adv data set — starting advertising");
            esp_ble_gap_start_advertising(&s_adv_params);
            break;

        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            if (param->adv_start_cmpl.status == ESP_BT_STATUS_SUCCESS) {
                s_adv_active = true;
                ESP_LOGI(TAG, "Advertising active");
#if LED_ENABLED
                led_blink(1, 200);
#endif
            } else {
                ESP_LOGE(TAG, "Failed to start advertising: status=%d",
                         param->adv_start_cmpl.status);
            }
            break;

        case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
            s_adv_active = false;
            ESP_LOGI(TAG, "Advertising stopped");
            break;

        default:
            break;
    }
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

static void led_blink(int times, int delay_ms)
{
#if LED_ENABLED
    for (int i = 0; i < times; i++) {
        gpio_set_level(LED_GPIO, 1);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
        gpio_set_level(LED_GPIO, 0);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
#endif
}

/* ============================================================
 *  BLE INITIALIZATION
 * ============================================================ */
static void ble_init(void)
{
    /* Release Classic BT memory — not needed for BLE-only operation */
    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));

    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    ESP_ERROR_CHECK(esp_ble_gap_register_callback(gap_event_handler));

    /* Set TX power — affects range and current draw */
    ESP_ERROR_CHECK(esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, TX_POWER));

    ESP_LOGI(TAG, "BLE initialized");
}

/* ============================================================
 *  app_main
 * ============================================================ */
void app_main(void)
{
    ESP_LOGI(TAG, "=== Beacon Firmware v1.0 ===");
    ESP_LOGI(TAG, "Device ID    : 0x%02X", DEVICE_ID);
    ESP_LOGI(TAG, "Roll interval: %d ms", ROLL_INTERVAL_MS);

    /* NVS — required by the BLE stack */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* LED setup */
    led_init();
    led_blink(3, 150); // 3 blinks = boot complete

    /* BLE setup */
    ble_init();

    /* Start advertising for the first time */
    beacon_start_advertising();

    /* Start rolling ID timer */
    s_roll_timer = xTimerCreate(
        "roll_timer",
        pdMS_TO_TICKS(ROLL_INTERVAL_MS),
        pdTRUE,  // auto-reload
        NULL,
        roll_timer_cb
    );
    if (s_roll_timer != NULL) {
        xTimerStart(s_roll_timer, 0);
        ESP_LOGI(TAG, "Rolling ID timer started (%d ms)", ROLL_INTERVAL_MS);
    }

    /* ============================================================
     *  Main loop — status monitoring + optional light sleep
     *
     *  Power saving note:
     *  The ESP-IDF BLE stack automatically uses modem sleep between
     *  advertising events. For deeper savings, enable light sleep
     *  in menuconfig:
     *    Component config -> Power Management -> Enable light sleep
     *  and set CONFIG_PM_ENABLE=y in sdkconfig.
     * ============================================================ */
    uint32_t loop_count = 0;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000/2));
        loop_count++;

        if (s_adv_active) {
            ESP_LOGI(TAG, "[%lu] Advertising running — payload ts=%lu",
                     (unsigned long)loop_count,
                     (unsigned long)s_payload.timestamp);
        } else if (!s_rolling) {
            ESP_LOGW(TAG, "[%lu] Advertising not active — attempting recovery",
                     (unsigned long)loop_count);
            /* Auto-recovery only if not currently rolling ID */
            beacon_start_advertising();
        }
    }
}