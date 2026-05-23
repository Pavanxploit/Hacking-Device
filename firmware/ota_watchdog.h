#pragma once
// ─── OTA updater ──────────────────────────────────────────────────────────
#include <Arduino.h>

void ota_init();
void ota_handle();   // call in loop() — non-blocking check

// ─── Watchdog ─────────────────────────────────────────────────────────────
void watchdog_init();
void watchdog_feed();  // call after every successful scan cycle
