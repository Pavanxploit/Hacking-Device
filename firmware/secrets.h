#pragma once

// ─── Copy this file to secrets.h and fill in your values ──────────────────
// secrets.h is in .gitignore — never commit it

// Your home/lab WiFi (ESP32 uses this to reach the laptop backend)
#define WIFI_SSID      "YOUR_WIFI_SSID"
#define WIFI_PASSWORD  "YOUR_WIFI_PASSWORD"

// Your laptop's LAN IP — run `ip a` or `ipconfig` to find it
// Must be on the same network as the ESP32
// Example: "192.168.1.42"
#define BACKEND_IP     "YOUR_LAPTOP_IP"

// API key — must match API_KEY in your backend .env file
#define API_KEY        "wifighost-secret-key-change-me"

// OTA update password (used when flashing over WiFi via Arduino IDE)
#define OTA_PASSWORD   "wifighost-ota"
