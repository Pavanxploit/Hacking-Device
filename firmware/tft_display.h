#pragma once
#include <Arduino.h>
#include "config.h"

// Threat level enum used across all modules
enum ThreatLevel {
    THREAT_LVL_NONE     = 0,
    THREAT_LVL_LOW      = 1,
    THREAT_LVL_MEDIUM   = 2,
    THREAT_LVL_HIGH     = 3,
    THREAT_LVL_CRITICAL = 4
};

// Alert type strings matching backend response
struct AlertInfo {
    String  type;        // "EVIL_TWIN", "DEAUTH_FLOOD", "ROGUE_AP", etc.
    String  ssid;        // affected SSID
    String  bssid;       // attacker MAC
    uint8_t confidence;  // 0–100 from ML engine
    int8_t  rssi;        // signal strength
};

void tft_init();
void tft_draw_boot_screen();
void tft_draw_header(const String& ip, bool backend_ok);
void tft_draw_threat_meter(uint8_t score);
void tft_draw_alert(const AlertInfo& alert);
void tft_draw_no_alert();
void tft_add_log(const String& msg);
void tft_draw_scanning();
void tft_draw_wifi_connecting(const String& ssid);
void tft_draw_backend_error();
void tft_draw_network_count(uint8_t count);
uint16_t tft_threat_colour(uint8_t score);
