#include "tft_display.h"
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <SPI.h>

static Adafruit_ILI9341 tft(TFT_CS, TFT_DC, TFT_MOSI, TFT_CLK, TFT_RST, TFT_MISO);

static String  log_lines[MAX_LOG_LINES];
static uint8_t log_head   = 0;
static uint8_t log_count  = 0;

// ─── Internal helpers ──────────────────────────────────────────────────────

static void fill_rounded(int16_t x, int16_t y, int16_t w, int16_t h,
                          int16_t r, uint16_t col) {
    tft.fillRoundRect(x, y, w, h, r, col);
}

static void draw_label(int16_t x, int16_t y, const String& text,
                        uint8_t size, uint16_t col) {
    tft.setTextColor(col);
    tft.setTextSize(size);
    tft.setCursor(x, y);
    tft.print(text);
}

// ─── Colour by threat score ────────────────────────────────────────────────
uint16_t tft_threat_colour(uint8_t score) {
    if (score >= THREAT_CRITICAL) return COL_PURPLE;
    if (score >= THREAT_HIGH)     return COL_RED;
    if (score >= THREAT_MEDIUM)   return COL_ORANGE;
    if (score >= THREAT_LOW)      return COL_YELLOW;
    return COL_GREEN;
}

// ─── Init ─────────────────────────────────────────────────────────────────
void tft_init() {
    tft.begin();
    tft.setRotation(0);   // portrait, USB at bottom
    tft.fillScreen(COL_BG);
}

// ─── Boot splash ──────────────────────────────────────────────────────────
void tft_draw_boot_screen() {
    tft.fillScreen(COL_BG);

    // Logo box
    fill_rounded(20, 60, 200, 60, 8, COL_HEADER);
    tft.setTextColor(COL_CYAN);
    tft.setTextSize(3);
    tft.setCursor(30, 72);
    tft.print("WiFiGhost");
    tft.setTextColor(COL_SUBTEXT);
    tft.setTextSize(1);
    tft.setCursor(52, 100);
    tft.print("AI Threat Detector v2");

    // Divider
    tft.drawFastHLine(10, 135, 220, COL_BORDER);

    draw_label(10, 145, "Hardware:", 1, COL_SUBTEXT);
    draw_label(10, 158, "ESP32 DevKit V1 (30-pin)", 1, COL_TEXT);
    draw_label(10, 172, "ILI9341 2.8\" TFT 240x320", 1, COL_TEXT);

    draw_label(10, 192, "Sniffer:", 1, COL_SUBTEXT);
    draw_label(10, 205, "TL-WN722N v1 (AR9271)", 1, COL_TEXT);
    draw_label(10, 218, "Monitor mode + injection", 1, COL_TEXT);

    tft.drawFastHLine(10, 235, 220, COL_BORDER);
    draw_label(10, 242, "Booting...", 1, COL_CYAN);
}

// ─── Header bar ───────────────────────────────────────────────────────────
void tft_draw_header(const String& ip, bool backend_ok) {
    tft.fillRect(0, 0, SCREEN_W, HEADER_H, COL_HEADER);

    // Title
    tft.setTextColor(COL_CYAN);
    tft.setTextSize(1);
    tft.setCursor(4, 4);
    tft.print("WiFiGhost AI");

    // Backend status dot
    uint16_t dot_col = backend_ok ? COL_GREEN : COL_RED;
    tft.fillCircle(SCREEN_W - 8, 8, 5, dot_col);

    // IP address
    tft.setTextColor(COL_SUBTEXT);
    tft.setTextSize(1);
    tft.setCursor(4, 18);
    tft.print(ip.length() > 0 ? ip : "No IP");

    // Status text
    tft.setCursor(SCREEN_W - 68, 18);
    tft.setTextColor(backend_ok ? COL_GREEN : COL_RED);
    tft.print(backend_ok ? "ONLINE " : "OFFLINE");
}

// ─── Animated threat meter ────────────────────────────────────────────────
void tft_draw_threat_meter(uint8_t score) {
    const int16_t bx = 10, by = METER_Y;
    const int16_t bw = SCREEN_W - 20, bh = METER_H;

    // Background track
    fill_rounded(bx, by, bw, bh, 4, COL_BORDER);

    // Filled portion
    uint16_t fill_w = (uint32_t)score * bw / 100;
    if (fill_w > 0) {
        fill_rounded(bx, by, fill_w, bh, 4, tft_threat_colour(score));
    }

    // Score text centred in bar
    tft.setTextColor(COL_TEXT);
    tft.setTextSize(1);
    String label = "THREAT: " + String(score) + "%";
    int16_t tx = bx + (bw - label.length() * 6) / 2;
    tft.setCursor(tx, by + (bh - 8) / 2);
    tft.print(label);

    // Threat label below bar
    tft.fillRect(bx, by + bh + 4, bw, 10, COL_BG);
    tft.setTextColor(tft_threat_colour(score));
    tft.setCursor(bx, by + bh + 4);
    if      (score >= THREAT_CRITICAL) tft.print("CRITICAL — TAKE ACTION NOW");
    else if (score >= THREAT_HIGH)     tft.print("HIGH — Active attack detected");
    else if (score >= THREAT_MEDIUM)   tft.print("MEDIUM — Suspicious activity");
    else if (score >= THREAT_LOW)      tft.print("LOW — Anomaly noted");
    else                               tft.print("CLEAR — Environment normal");
}

// ─── Alert detail card ────────────────────────────────────────────────────
void tft_draw_alert(const AlertInfo& alert) {
    const int16_t ax = 10, ay = ALERT_Y;
    const int16_t aw = SCREEN_W - 20;

    tft.fillRect(ax, ay, aw, 70, COL_BG);
    fill_rounded(ax, ay, aw, 70, 6, COL_HEADER);

    // Alert type badge
    uint16_t badge_col = tft_threat_colour(alert.confidence);
    fill_rounded(ax + 4, ay + 4, aw - 8, 16, 3, badge_col);
    tft.setTextColor(COL_BG);
    tft.setTextSize(1);
    int16_t tx = ax + 4 + ((aw - 8) - alert.type.length() * 6) / 2;
    tft.setCursor(tx, ay + 8);
    tft.print(alert.type);

    // SSID
    tft.setTextColor(COL_TEXT);
    tft.setCursor(ax + 4, ay + 26);
    tft.print("SSID: ");
    tft.setTextColor(COL_CYAN);
    String ssid_disp = alert.ssid.length() > 18 ?
                       alert.ssid.substring(0, 17) + "~" : alert.ssid;
    tft.print(ssid_disp);

    // BSSID + confidence
    tft.setTextColor(COL_SUBTEXT);
    tft.setCursor(ax + 4, ay + 40);
    tft.print("MAC: ");
    tft.print(alert.bssid.length() > 0 ? alert.bssid : "unknown");

    tft.setTextColor(badge_col);
    tft.setCursor(ax + 4, ay + 54);
    tft.print("Confidence: ");
    tft.print(String(alert.confidence) + "%");
    tft.setTextColor(COL_SUBTEXT);
    tft.print("  RSSI: " + String(alert.rssi) + "dBm");
}

// ─── No alert state ───────────────────────────────────────────────────────
void tft_draw_no_alert() {
    const int16_t ax = 10, ay = ALERT_Y;
    const int16_t aw = SCREEN_W - 20;
    tft.fillRect(ax, ay, aw, 70, COL_BG);
    fill_rounded(ax, ay, aw, 70, 6, COL_HEADER);
    tft.setTextColor(COL_GREEN);
    tft.setTextSize(1);
    tft.setCursor(ax + 30, ay + 20);
    tft.print("No active threats");
    tft.setTextColor(COL_SUBTEXT);
    tft.setCursor(ax + 14, ay + 38);
    tft.print("Monitoring Wi-Fi environment");
}

// ─── Network count badge ──────────────────────────────────────────────────
void tft_draw_network_count(uint8_t count) {
    tft.fillRect(SCREEN_W - 70, METER_Y - 16, 60, 14, COL_BG);
    tft.setTextColor(COL_SUBTEXT);
    tft.setTextSize(1);
    tft.setCursor(SCREEN_W - 70, METER_Y - 14);
    tft.print("APs: ");
    tft.setTextColor(COL_CYAN);
    tft.print(count);
}

// ─── Scanning animation ───────────────────────────────────────────────────
void tft_draw_scanning() {
    static uint8_t dots = 0;
    dots = (dots + 1) % 4;
    tft.fillRect(10, METER_Y - 16, 120, 12, COL_BG);
    tft.setTextColor(COL_CYAN);
    tft.setTextSize(1);
    tft.setCursor(10, METER_Y - 14);
    String s = "Scanning";
    for (uint8_t i = 0; i < dots; i++) s += ".";
    tft.print(s);
}

// ─── WiFi connecting screen ───────────────────────────────────────────────
void tft_draw_wifi_connecting(const String& ssid) {
    tft.fillRect(0, HEADER_H, SCREEN_W, 60, COL_BG);
    tft.setTextColor(COL_YELLOW);
    tft.setTextSize(1);
    tft.setCursor(10, HEADER_H + 8);
    tft.print("Connecting to WiFi...");
    tft.setTextColor(COL_TEXT);
    tft.setCursor(10, HEADER_H + 22);
    tft.print(ssid);
}

// ─── Backend error screen ─────────────────────────────────────────────────
void tft_draw_backend_error() {
    tft.fillRect(10, ALERT_Y, SCREEN_W - 20, 70, COL_BG);
    fill_rounded(10, ALERT_Y, SCREEN_W - 20, 70, 6, 0x2000);
    tft.setTextColor(COL_RED);
    tft.setTextSize(1);
    tft.setCursor(16, ALERT_Y + 8);
    tft.print("Backend unreachable");
    tft.setTextColor(COL_SUBTEXT);
    tft.setCursor(16, ALERT_Y + 24);
    tft.print("Check laptop IP in secrets.h");
    tft.setCursor(16, ALERT_Y + 38);
    tft.print("Is Gunicorn running?");
}

// ─── Scrolling log panel ──────────────────────────────────────────────────
void tft_add_log(const String& msg) {
    log_lines[log_head] = msg;
    log_head = (log_head + 1) % MAX_LOG_LINES;
    if (log_count < MAX_LOG_LINES) log_count++;

    // Redraw log area
    tft.fillRect(0, LOG_Y, SCREEN_W, SCREEN_H - LOG_Y, COL_BG);
    tft.drawFastHLine(4, LOG_Y - 2, SCREEN_W - 8, COL_BORDER);
    tft.setTextColor(COL_SUBTEXT);
    tft.setTextSize(1);
    tft.setCursor(4, LOG_Y - 12);
    tft.print("Event log");

    uint8_t start = (log_head + MAX_LOG_LINES - log_count) % MAX_LOG_LINES;
    for (uint8_t i = 0; i < log_count; i++) {
        uint8_t idx = (start + i) % MAX_LOG_LINES;
        uint16_t col = (i == log_count - 1) ? COL_TEXT : COL_SUBTEXT;
        tft.setTextColor(col);
        tft.setCursor(4, LOG_Y + i * LOG_LINE_H);
        String line = log_lines[idx];
        if (line.length() > 38) line = line.substring(0, 37) + "~";
        tft.print(line);
    }
}
