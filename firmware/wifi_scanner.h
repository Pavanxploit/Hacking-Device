#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>
#include "config.h"
#include "tft_display.h"

struct ScanResult {
    bool    success;
    uint8_t threat_score;   // 0–100 from backend ML engine
    AlertInfo alert;        // populated only when threat_score >= THREAT_LOW
    bool    has_alert;
    uint8_t network_count;
};

// Connect to WiFi — blocks until connected or timeout
bool wifi_connect();

// Returns true if WiFi is still connected
bool wifi_check();

// Perform a WiFi scan, POST to backend, return parsed result
ScanResult wifi_scan_and_post();

// Returns current local IP as string
String wifi_local_ip();
