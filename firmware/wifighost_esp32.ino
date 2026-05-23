/*
 * WiFiGhost AI v2 — ESP32 Firmware
 * Hardware: ESP32 DevKit V1 (30-pin) + ILI9341 2.8" TFT (240x320)
 * Companion: TL-WN722N v1 (AR9271) runs on laptop in monitor mode
 *
 * Libraries required (install via Arduino IDE Library Manager):
 *   - Adafruit GFX Library       by Adafruit
 *   - Adafruit ILI9341           by Adafruit
 *   - ArduinoJson                by Benoit Blanchon  (v6.x)
 *   - ArduinoOTA                 (built into ESP32 Arduino core)
 *
 * Board: "ESP32 Dev Module" in Arduino IDE
 * Flash: 4MB, Partition: Default (no OTA) or Minimal SPIFFS (with OTA)
 */

#include <Arduino.h>
#include <WiFi.h>
#include "config.h"
#include "secrets.h"
#include "tft_display.h"
#include "wifi_scanner.h"
#include "ota_watchdog.h"

// ─── State machine ────────────────────────────────────────────────────────
enum State {
    STATE_BOOT,
    STATE_WIFI_CONNECTING,
    STATE_RUNNING,
    STATE_WIFI_LOST,
    STATE_BACKEND_ERROR
};

static State      current_state   = STATE_BOOT;
static uint32_t   last_scan_ms    = 0;
static uint32_t   last_reconnect  = 0;
static uint8_t    consecutive_errors = 0;
static uint8_t    current_score   = 0;
static bool       backend_online  = false;

#define MAX_ERRORS  3   // backend errors before showing error screen

// ─── Buzzer alert (optional) ──────────────────────────────────────────────
static void buzz_alert(uint8_t score) {
    if (!BUZZER_ENABLED) return;
    if (score >= THREAT_HIGH) {
        // Three short beeps for high/critical
        for (uint8_t i = 0; i < 3; i++) {
            digitalWrite(BUZZER_PIN, HIGH);
            delay(80);
            digitalWrite(BUZZER_PIN, LOW);
            delay(80);
        }
    } else if (score >= THREAT_MEDIUM) {
        // One beep for medium
        digitalWrite(BUZZER_PIN, HIGH);
        delay(200);
        digitalWrite(BUZZER_PIN, LOW);
    }
}

// ─── Status LED ───────────────────────────────────────────────────────────
static void update_led(uint8_t score) {
    // Blink rate encodes threat level
    static uint32_t led_ms  = 0;
    static bool     led_on  = false;
    uint16_t period = (score >= THREAT_HIGH)   ? 150 :
                      (score >= THREAT_MEDIUM)  ? 400 :
                      (score >= THREAT_LOW)     ? 800 : 2000;

    if (millis() - led_ms > period) {
        led_on = !led_on;
        digitalWrite(STATUS_LED_PIN, led_on ? HIGH : LOW);
        led_ms = millis();
    }
}

// ─── Handle scan result ───────────────────────────────────────────────────
static void handle_result(const ScanResult& result) {
    if (!result.success) {
        consecutive_errors++;
        backend_online = false;
        tft_add_log("[ERR] Backend POST failed");
        if (consecutive_errors >= MAX_ERRORS) {
            current_state = STATE_BACKEND_ERROR;
            tft_draw_backend_error();
        }
        return;
    }

    consecutive_errors = 0;
    backend_online     = true;
    current_score      = result.threat_score;

    // Update header + meter
    tft_draw_header(wifi_local_ip(), true);
    tft_draw_network_count(result.network_count);
    tft_draw_threat_meter(result.threat_score);

    // Show alert or clear card
    if (result.has_alert) {
        tft_draw_alert(result.alert);
        buzz_alert(result.threat_score);
        tft_add_log("[" + result.alert.type + "] " + result.alert.ssid
                    + " " + String(result.alert.confidence) + "%");
    } else {
        tft_draw_no_alert();
        tft_add_log("[OK] " + String(result.network_count)
                    + " APs, score=" + String(result.threat_score));
    }
}

// ─── Setup ────────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);
    Serial.println("\n[WiFiGhost AI v2] Booting...");

    // GPIO init
    pinMode(STATUS_LED_PIN, OUTPUT);
    if (BUZZER_ENABLED) pinMode(BUZZER_PIN, OUTPUT);

    // TFT init + boot screen
    tft_init();
    tft_draw_boot_screen();
    delay(2000);

    // Watchdog — must feed every WDT_TIMEOUT_SEC seconds
    watchdog_init();

    // WiFi connect
    current_state = STATE_WIFI_CONNECTING;
    tft_draw_wifi_connecting(WIFI_SSID);

    if (wifi_connect()) {
        Serial.println("[WiFi] Connected: " + wifi_local_ip());
        tft_add_log("[WiFi] " + wifi_local_ip());

        // OTA — only starts after WiFi is up
        ota_init();

        // Full UI frame
        tft.fillScreen(COL_BG);
        tft_draw_header(wifi_local_ip(), false);
        tft_draw_threat_meter(0);
        tft_draw_no_alert();
        tft_add_log("[SYS] WiFiGhost ready");

        current_state = STATE_RUNNING;
    } else {
        Serial.println("[WiFi] Connection failed!");
        tft_add_log("[ERR] WiFi failed - retrying");
        current_state = STATE_WIFI_LOST;
    }

    watchdog_feed();
}

// ─── Loop ─────────────────────────────────────────────────────────────────
void loop() {
    ota_handle();          // non-blocking OTA check
    update_led(current_score);

    switch (current_state) {

        // ── Connected and running ─────────────────────────────────────────
        case STATE_RUNNING: {
            if (!wifi_check()) {
                current_state  = STATE_WIFI_LOST;
                backend_online = false;
                tft_draw_header("", false);
                tft_add_log("[WiFi] Connection lost");
                break;
            }

            if (millis() - last_scan_ms >= SCAN_INTERVAL_MS) {
                last_scan_ms = millis();
                tft_draw_scanning();

                ScanResult result = wifi_scan_and_post();
                handle_result(result);

                // Re-enter running from error state on success
                if (result.success && current_state == STATE_BACKEND_ERROR) {
                    current_state = STATE_RUNNING;
                }

                watchdog_feed();
            }
            break;
        }

        // ── WiFi lost — keep trying to reconnect ──────────────────────────
        case STATE_WIFI_LOST:
        case STATE_WIFI_CONNECTING: {
            if (millis() - last_reconnect >= RECONNECT_INTERVAL_MS) {
                last_reconnect = millis();
                tft_draw_wifi_connecting(WIFI_SSID);
                tft_add_log("[WiFi] Reconnecting...");

                if (wifi_connect()) {
                    tft_add_log("[WiFi] " + wifi_local_ip());
                    tft_draw_header(wifi_local_ip(), false);
                    consecutive_errors = 0;
                    current_state      = STATE_RUNNING;
                }
                watchdog_feed();
            }
            break;
        }

        // ── Backend error — keep scanning, auto-recover ───────────────────
        case STATE_BACKEND_ERROR: {
            if (!wifi_check()) {
                current_state = STATE_WIFI_LOST;
                break;
            }
            if (millis() - last_scan_ms >= SCAN_INTERVAL_MS * 2) {
                last_scan_ms = millis();
                ScanResult result = wifi_scan_and_post();
                handle_result(result);
                watchdog_feed();
            }
            break;
        }

        case STATE_BOOT:
        default:
            break;
    }

    delay(10);
}
