#include "wifi_scanner.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "secrets.h"

static const char* BACKEND_URL = "http://" BACKEND_IP ":" + String(API_PORT) + API_PATH;

// ─── WiFi connect ─────────────────────────────────────────────────────────
bool wifi_connect() {
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - start > 15000) return false;
        delay(250);
    }
    return true;
}

bool wifi_check() {
    return WiFi.status() == WL_CONNECTED;
}

String wifi_local_ip() {
    return WiFi.localIP().toString();
}

// ─── Build scan JSON payload ───────────────────────────────────────────────
static String build_scan_json(int network_count) {
    // Use a larger doc for up to MAX_NETWORKS_PER_SCAN networks
    DynamicJsonDocument doc(4096);

    doc["device_id"]  = "esp32-wifighost-v2";
    doc["firmware"]   = "2.0.0";
    doc["chip_id"]    = String((uint32_t)ESP.getEfuseMac(), HEX);
    doc["free_heap"]  = ESP.getFreeHeap();
    doc["rssi_self"]  = WiFi.RSSI();   // own connection strength
    doc["timestamp"]  = millis();

    JsonArray nets = doc.createNestedArray("networks");

    int count = min(network_count, MAX_NETWORKS_PER_SCAN);
    for (int i = 0; i < count; i++) {
        JsonObject net = nets.createNestedObject();
        net["ssid"]       = WiFi.SSID(i);
        net["bssid"]      = WiFi.BSSIDstr(i);
        net["rssi"]       = WiFi.RSSI(i);
        net["channel"]    = WiFi.channel(i);
        net["encryption"] = (int)WiFi.encryptionType(i);  // WIFI_AUTH_* enum

        // Human-readable encryption
        switch (WiFi.encryptionType(i)) {
            case WIFI_AUTH_OPEN:         net["enc_str"] = "OPEN";   break;
            case WIFI_AUTH_WEP:          net["enc_str"] = "WEP";    break;
            case WIFI_AUTH_WPA_PSK:      net["enc_str"] = "WPA";    break;
            case WIFI_AUTH_WPA2_PSK:     net["enc_str"] = "WPA2";   break;
            case WIFI_AUTH_WPA_WPA2_PSK: net["enc_str"] = "WPA/2";  break;
            case WIFI_AUTH_WPA3_PSK:     net["enc_str"] = "WPA3";   break;
            default:                     net["enc_str"] = "UNKNOWN"; break;
        }
    }

    String out;
    serializeJson(doc, out);
    return out;
}

// ─── Parse backend response ────────────────────────────────────────────────
static ScanResult parse_response(const String& body, uint8_t network_count) {
    ScanResult result;
    result.success       = true;
    result.network_count = network_count;
    result.has_alert     = false;
    result.threat_score  = 0;

    DynamicJsonDocument doc(1024);
    DeserializationError err = deserializeJson(doc, body);
    if (err) {
        result.success = false;
        return result;
    }

    result.threat_score = doc["threat_score"] | 0;

    // Parse alert if present
    if (doc.containsKey("alert") && !doc["alert"].isNull()) {
        result.has_alert         = true;
        result.alert.type        = doc["alert"]["type"]       | "UNKNOWN";
        result.alert.ssid        = doc["alert"]["ssid"]       | "";
        result.alert.bssid       = doc["alert"]["bssid"]      | "";
        result.alert.confidence  = doc["alert"]["confidence"] | 0;
        result.alert.rssi        = doc["alert"]["rssi"]       | 0;
    }

    return result;
}

// ─── Main scan + POST ─────────────────────────────────────────────────────
ScanResult wifi_scan_and_post() {
    ScanResult fail_result;
    fail_result.success = false;

    // Trigger scan — disconnect from AP briefly (scanNetworks blocks)
    int n = WiFi.scanNetworks(false, true);  // async=false, show_hidden=true
    if (n == WIFI_SCAN_FAILED || n < 0) {
        fail_result.network_count = 0;
        return fail_result;
    }

    String payload = build_scan_json(n);

    // POST to backend
    HTTPClient http;
    String url = String("http://") + BACKEND_IP + ":" + API_PORT + API_PATH;
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-API-Key", API_KEY);
    http.setTimeout(HTTP_TIMEOUT_MS);

    int code = http.POST(payload);

    if (code != 200) {
        http.end();
        fail_result.network_count = (uint8_t)n;
        return fail_result;
    }

    String response = http.getString();
    http.end();

    // Free scan data
    WiFi.scanDelete();

    return parse_response(response, (uint8_t)n);
}
