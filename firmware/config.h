#pragma once

// ─── TFT ILI9341 SPI Pin Map (ESP32 DevKit V1 30-pin) ─────────────────────
#define TFT_CS    5
#define TFT_DC    21
#define TFT_RST   22
#define TFT_MOSI  23
#define TFT_CLK   18
#define TFT_MISO  19
#define TFT_LED   -1   // tie TFT backlight to 3V3 directly

// ─── Status LED (built-in on most DevKit V1 boards) ───────────────────────
#define STATUS_LED_PIN  2

// ─── Buzzer (optional — connect to this GPIO + GND) ───────────────────────
#define BUZZER_PIN      4
#define BUZZER_ENABLED  false   // set true if buzzer is wired

// ─── Network ──────────────────────────────────────────────────────────────
#define HTTP_TIMEOUT_MS       5000
#define SCAN_INTERVAL_MS      8000    // how often ESP32 sends a scan
#define RECONNECT_INTERVAL_MS 10000   // WiFi reconnect retry
#define MAX_NETWORKS_PER_SCAN 20      // cap JSON payload size

// ─── Backend API ──────────────────────────────────────────────────────────
// Set BACKEND_IP in secrets.h — this is the laptop IP on LAN
#define API_PATH        "/api/scan"
#define HEALTH_PATH     "/api/health"
#define API_PORT        5000

// ─── OTA ──────────────────────────────────────────────────────────────────
#define OTA_HOSTNAME    "wifighost-esp32"
#define OTA_PORT        3232

// ─── Watchdog ─────────────────────────────────────────────────────────────
#define WDT_TIMEOUT_SEC  30

// ─── TFT UI Layout ────────────────────────────────────────────────────────
#define SCREEN_W        240
#define SCREEN_H        320
#define HEADER_H        36
#define METER_Y         50
#define METER_H         30
#define ALERT_Y         100
#define LOG_Y           180
#define LOG_LINE_H      18
#define MAX_LOG_LINES   6

// ─── Threat level thresholds (0–100 score from backend) ───────────────────
#define THREAT_NONE     0
#define THREAT_LOW      30
#define THREAT_MEDIUM   60
#define THREAT_HIGH     80
#define THREAT_CRITICAL 95

// ─── TFT Colours (RGB565) ─────────────────────────────────────────────────
#define COL_BG          0x0841   // near-black
#define COL_HEADER      0x1082   // dark blue-grey
#define COL_TEXT        0xFFFF   // white
#define COL_SUBTEXT     0xAD55   // grey
#define COL_GREEN       0x07E0
#define COL_YELLOW      0xFFE0
#define COL_ORANGE      0xFD20
#define COL_RED         0xF800
#define COL_CYAN        0x07FF
#define COL_PURPLE      0x801F
#define COL_BORDER      0x2104   // dim grey border
