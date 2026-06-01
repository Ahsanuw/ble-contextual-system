idf_component_register(
        SRCS "main.c"
        INCLUDE_DIRS "."
        EMBED_FILES
        "dashboard.html"
        REQUIRES
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        esp_timer
        esp_http_server
        mqtt
        json
        driver
)