#include "ota_watchdog.h"
#include <ArduinoOTA.h>
#include <esp_task_wdt.h>
#include "config.h"
#include "secrets.h"
#include "tft_display.h"

// ─── OTA ──────────────────────────────────────────────────────────────────
void ota_init() {
    ArduinoOTA.setHostname(OTA_HOSTNAME);
    ArduinoOTA.setPassword(OTA_PASSWORD);
    ArduinoOTA.setPort(OTA_PORT);

    ArduinoOTA.onStart([]() {
        tft_add_log("[OTA] Update starting...");
    });

    ArduinoOTA.onEnd([]() {
        tft_add_log("[OTA] Done. Rebooting.");
    });

    ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
        static uint8_t last_pct = 255;
        uint8_t pct = (progress * 100) / total;
        if (pct != last_pct && pct % 10 == 0) {
            tft_add_log("[OTA] " + String(pct) + "%");
            last_pct = pct;
        }
    });

    ArduinoOTA.onError([](ota_error_t error) {
        String msg = "[OTA] Error: ";
        switch (error) {
            case OTA_AUTH_ERROR:    msg += "Auth failed";    break;
            case OTA_BEGIN_ERROR:   msg += "Begin failed";   break;
            case OTA_CONNECT_ERROR: msg += "Connect failed"; break;
            case OTA_RECEIVE_ERROR: msg += "Receive failed"; break;
            case OTA_END_ERROR:     msg += "End failed";     break;
        }
        tft_add_log(msg);
    });

    ArduinoOTA.begin();
    tft_add_log("[OTA] Ready on " + String(OTA_HOSTNAME));
}

void ota_handle() {
    ArduinoOTA.handle();
}

// ─── Watchdog ─────────────────────────────────────────────────────────────
void watchdog_init() {
    esp_task_wdt_init(WDT_TIMEOUT_SEC, true);  // true = panic on timeout
    esp_task_wdt_add(NULL);                     // watch current task
}

void watchdog_feed() {
    esp_task_wdt_reset();
}
