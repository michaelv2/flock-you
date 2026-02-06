#include <Arduino.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <NimBLEAdvertisedDevice.h>
#include <ArduinoJson.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"

#ifdef HAS_TFT
#include <Adafruit_GFX.h>
#include <Adafruit_ST7789.h>
#include <SPI.h>
#endif

// ============================================================================
// CONFIGURATION
// ============================================================================

// Hardware Configuration
#ifdef BUZZER_PIN_OVERRIDE
#define BUZZER_PIN BUZZER_PIN_OVERRIDE
#else
#define BUZZER_PIN 3  // GPIO3 (D2) - PWM capable pin on Xiao ESP32 S3
#endif

// Audio Configuration
#define LOW_FREQ 200      // Boot sequence - low pitch
#define HIGH_FREQ 800     // Boot sequence - high pitch & detection alert
#define DETECT_FREQ 1000  // Detection alert - high pitch (faster beeps)
#define HEARTBEAT_FREQ 600 // Heartbeat pulse frequency
#define BOOT_BEEP_DURATION 300   // Boot beep duration
#define DETECT_BEEP_DURATION 150 // Detection beep duration (faster)
#define HEARTBEAT_DURATION 100   // Short heartbeat pulse

// WiFi Promiscuous Mode Configuration
#define MAX_CHANNEL 13
#define CHANNEL_HOP_INTERVAL 500  // milliseconds

// BLE SCANNING CONFIGURATION
#define BLE_SCAN_DURATION 1    // Seconds
#define BLE_SCAN_INTERVAL 5000 // Milliseconds between scans
static unsigned long last_ble_scan = 0;

// Detection Pattern Limits
#define MAX_SSID_PATTERNS 10
#define MAX_MAC_PATTERNS 50
#define MAX_DEVICE_NAMES 20

// Verbose Mode Configuration
#define VERBOSE_BUTTON_PIN 0       // GPIO0 (Boot button on all variants)
#define VERBOSE_DEBOUNCE_MS 300    // Software debounce for button
#define VERBOSE_WIFI_MAX_MACS 32   // Max unique MACs tracked per channel dwell
#define VERBOSE_WIFI_TOP_N 5       // Top N devices by frame count in summary
#define VERBOSE_BLE_MAX_DEVICES 20 // Max BLE devices buffered per scan
#define VERBOSE_BLE_OUTPUT_CAP 10  // Max BLE devices in output JSON

// ============================================================================
// DETECTION PATTERNS (Extracted from Real Flock Safety Device Databases)
// ============================================================================

// WiFi SSID patterns to detect (case-insensitive)
static const char* wifi_ssid_patterns[] = {
    "flock",        // Standard Flock Safety naming
    "Flock",        // Capitalized variant
    "FLOCK",        // All caps variant
    "FS Ext Battery", // Flock Safety Extended Battery devices
    "Penguin",      // Penguin surveillance devices
    "Pigvision"     // Pigvision surveillance systems
};

// Known Flock Safety MAC address prefixes (from real device databases)
static const char* mac_prefixes[] = {
    // FS Ext Battery devices
    "58:8e:81", "cc:cc:cc", "ec:1b:bd", "90:35:ea", "04:0d:84", 
    "f0:82:c0", "1c:34:f1", "38:5b:44", "94:34:69", "b4:e3:f9",
    
    // Flock WiFi devices
    "70:c9:4e", "3c:91:80", "d8:f3:bc", "80:30:49", "14:5a:fc",
    "74:4c:a1", "08:3a:88", "9c:2f:9d", "94:08:53", "e4:aa:ea"
    
    // Penguin devices - these are NOT OUI based, so use local ouis
    // from the wigle.net db relative to your location 
    // "cc:09:24", "ed:c7:63", "e8:ce:56", "ea:0c:ea", "d8:8f:14",
    // "f9:d9:c0", "f1:32:f9", "f6:a0:76", "e4:1c:9e", "e7:f2:43",
    // "e2:71:33", "da:91:a9", "e1:0e:15", "c8:ae:87", "f4:ed:b2",
    // "d8:bf:b5", "ee:8f:3c", "d7:2b:21", "ea:5a:98"
};

// Device name patterns for BLE advertisement detection
static const char* device_name_patterns[] = {
    "FS Ext Battery",  // Flock Safety Extended Battery
    "Penguin",         // Penguin surveillance devices
    "Flock",           // Standard Flock Safety devices
    "Pigvision"        // Pigvision surveillance systems
};

// ============================================================================
// RAVEN SURVEILLANCE DEVICE UUID PATTERNS
// ============================================================================
// These UUIDs are specific to Raven surveillance devices (acoustic gunshot detection)
// Source: raven_configurations.json - firmware versions 1.1.7, 1.2.0, 1.3.1

// Raven Device Information Service (used across all firmware versions)
#define RAVEN_DEVICE_INFO_SERVICE       "0000180a-0000-1000-8000-00805f9b34fb"

// Raven GPS Location Service (firmware 1.2.0+)
#define RAVEN_GPS_SERVICE               "00003100-0000-1000-8000-00805f9b34fb"

// Raven Power/Battery Service (firmware 1.2.0+)
#define RAVEN_POWER_SERVICE             "00003200-0000-1000-8000-00805f9b34fb"

// Raven Network Status Service (firmware 1.2.0+)
#define RAVEN_NETWORK_SERVICE           "00003300-0000-1000-8000-00805f9b34fb"

// Raven Upload Statistics Service (firmware 1.2.0+)
#define RAVEN_UPLOAD_SERVICE            "00003400-0000-1000-8000-00805f9b34fb"

// Raven Error/Failure Service (firmware 1.2.0+)
#define RAVEN_ERROR_SERVICE             "00003500-0000-1000-8000-00805f9b34fb"

// Health Thermometer Service (firmware 1.1.7)
#define RAVEN_OLD_HEALTH_SERVICE        "00001809-0000-1000-8000-00805f9b34fb"

// Location and Navigation Service (firmware 1.1.7)
#define RAVEN_OLD_LOCATION_SERVICE      "00001819-0000-1000-8000-00805f9b34fb"

// Known Raven service UUIDs for detection
static const char* raven_service_uuids[] = {
    RAVEN_DEVICE_INFO_SERVICE,    // Device info (all versions)
    RAVEN_GPS_SERVICE,            // GPS data (1.2.0+)
    RAVEN_POWER_SERVICE,          // Battery/Solar (1.2.0+)
    RAVEN_NETWORK_SERVICE,        // LTE/WiFi status (1.2.0+)
    RAVEN_UPLOAD_SERVICE,         // Upload stats (1.2.0+)
    RAVEN_ERROR_SERVICE,          // Error tracking (1.2.0+)
    RAVEN_OLD_HEALTH_SERVICE,     // Old health service (1.1.7)
    RAVEN_OLD_LOCATION_SERVICE    // Old location service (1.1.7)
};

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

static uint8_t current_channel = 1;
static unsigned long last_channel_hop = 0;
static bool triggered = false;
static bool device_in_range = false;
static unsigned long last_detection_time = 0;
static unsigned long last_heartbeat = 0;
static NimBLEScan* pBLEScan;

// ============================================================================
// VERBOSE MODE STATE
// ============================================================================

static volatile bool verbose_mode = false;
static volatile unsigned long last_button_press = 0;

// WiFi per-channel-dwell stats
struct WifiDeviceStats {
    uint8_t mac[6];
    char ssid[33];
    int rssi_sum;
    int rssi_best;
    uint16_t frame_count;
    bool is_probe;  // true = probe request, false = beacon
};

static struct {
    WifiDeviceStats devices[VERBOSE_WIFI_MAX_MACS];
    uint8_t device_count;
    uint32_t total_frames;
    uint32_t probe_count;
    uint32_t beacon_count;
} wifi_stats;

// BLE per-scan buffer for non-matched devices
struct BleDeviceEntry {
    char mac[18];
    char name[33];
    int rssi;
    bool has_name;
};

static struct {
    BleDeviceEntry devices[VERBOSE_BLE_MAX_DEVICES];
    uint8_t device_count;
} ble_verbose_buffer;

#ifdef HAS_TFT
// Adafruit ESP32-S3 Reverse TFT Feather pin assignments
#define TFT_CS        42
#define TFT_DC        40
#define TFT_RST       41
#define TFT_BACKLITE  45
#define TFT_I2C_POWER 21

Adafruit_ST7789 tft = Adafruit_ST7789(TFT_CS, TFT_DC, TFT_RST);

// Display state
static volatile bool display_needs_update = false;
static volatile int last_rssi = -100;
static bool display_in_alert_mode = false;
static unsigned long last_display_update = 0;
#define DISPLAY_UPDATE_INTERVAL 250  // ms, throttle SPI writes

// Braille spinner: each byte is a bitmask of which dots to draw
// Bit-to-dot mapping follows Unicode braille pattern:
//   bit0=dot1(r0,c0) bit1=dot2(r1,c0) bit2=dot3(r2,c0)
//   bit3=dot4(r0,c1) bit4=dot5(r1,c1) bit5=dot6(r2,c1)
//   bit6=dot7(r3,c0) bit7=dot8(r3,c1)
static uint8_t spinner_frame = 0;
static const uint8_t spinner_patterns[] = {
    0xFE, // ⣾ all except dot 1
    0xFD, // ⣽ all except dot 2
    0xFB, // ⣻ all except dot 3
    0xBF, // ⢿ all except dot 7
    0x7F, // ⡿ all except dot 8
    0xDF, // ⣟ all except dot 6
    0xEF, // ⣯ all except dot 5
    0xF7, // ⣷ all except dot 4
};
#define SPINNER_FRAMES 8
#endif

// ============================================================================
// VERBOSE MODE BUTTON HANDLER
// ============================================================================

// Forward declaration (defined in Audio System section below)
void beep(int frequency, int duration_ms);

void IRAM_ATTR verbose_button_isr()
{
    unsigned long now = millis();
    if (now - last_button_press > VERBOSE_DEBOUNCE_MS) {
        verbose_mode = !verbose_mode;
        last_button_press = now;
    }
}

static bool verbose_pending_status = false;
static bool verbose_last_reported = false;

void verbose_check_status_change()
{
    if (verbose_mode != verbose_last_reported) {
        verbose_pending_status = true;
        verbose_last_reported = verbose_mode;
    }
    if (verbose_pending_status) {
        verbose_pending_status = false;
        // Emit status JSON
        StaticJsonDocument<128> doc;
        doc["type"] = "status";
        doc["verbose_mode"] = verbose_mode;
        serializeJson(doc, Serial);
        Serial.println();
        // Audio feedback: single beep = on, double beep = off
        if (verbose_mode) {
            beep(HIGH_FREQ, 100);
        } else {
            beep(HIGH_FREQ, 80);
            delay(60);
            beep(HIGH_FREQ, 80);
        }
    }
}

// Reset WiFi stats for a new channel dwell
void verbose_wifi_stats_reset()
{
    wifi_stats.device_count = 0;
    wifi_stats.total_frames = 0;
    wifi_stats.probe_count = 0;
    wifi_stats.beacon_count = 0;
}

// Track a WiFi frame in the stats struct (called from promiscuous callback)
void verbose_wifi_track_frame(const uint8_t* mac, const char* ssid, int rssi, bool is_probe)
{
    wifi_stats.total_frames++;
    if (is_probe) wifi_stats.probe_count++;
    else wifi_stats.beacon_count++;

    // Find existing entry or add new
    for (int i = 0; i < wifi_stats.device_count; i++) {
        if (memcmp(wifi_stats.devices[i].mac, mac, 6) == 0) {
            wifi_stats.devices[i].frame_count++;
            wifi_stats.devices[i].rssi_sum += rssi;
            if (rssi > wifi_stats.devices[i].rssi_best) {
                wifi_stats.devices[i].rssi_best = rssi;
            }
            // Update SSID if we now have one and didn't before
            if (ssid && ssid[0] && !wifi_stats.devices[i].ssid[0]) {
                strncpy(wifi_stats.devices[i].ssid, ssid, 32);
                wifi_stats.devices[i].ssid[32] = '\0';
            }
            return;
        }
    }
    // Add new device if space available
    if (wifi_stats.device_count < VERBOSE_WIFI_MAX_MACS) {
        WifiDeviceStats& d = wifi_stats.devices[wifi_stats.device_count];
        memcpy(d.mac, mac, 6);
        if (ssid && ssid[0]) {
            strncpy(d.ssid, ssid, 32);
            d.ssid[32] = '\0';
        } else {
            d.ssid[0] = '\0';
        }
        d.rssi_sum = rssi;
        d.rssi_best = rssi;
        d.frame_count = 1;
        d.is_probe = is_probe;
        wifi_stats.device_count++;
    }
}

// Emit WiFi verbose summary JSON for the completed channel dwell
void verbose_wifi_emit_summary(uint8_t channel)
{
    if (wifi_stats.total_frames == 0 && wifi_stats.device_count == 0) return;

    DynamicJsonDocument doc(1536);
    doc["type"] = "verbose";
    doc["protocol"] = "wifi";
    doc["channel"] = channel;
    doc["total_frames"] = wifi_stats.total_frames;
    doc["probe_count"] = wifi_stats.probe_count;
    doc["beacon_count"] = wifi_stats.beacon_count;
    doc["unique_macs"] = wifi_stats.device_count;

    // Sort devices by frame_count descending (simple selection sort for top N)
    // We only need the top VERBOSE_WIFI_TOP_N
    int top_count = min((int)wifi_stats.device_count, VERBOSE_WIFI_TOP_N);
    bool picked[VERBOSE_WIFI_MAX_MACS] = {false};

    JsonArray top = doc.createNestedArray("top_devices");
    for (int n = 0; n < top_count; n++) {
        int best_idx = -1;
        uint16_t best_frames = 0;
        for (int i = 0; i < wifi_stats.device_count; i++) {
            if (!picked[i] && wifi_stats.devices[i].frame_count > best_frames) {
                best_frames = wifi_stats.devices[i].frame_count;
                best_idx = i;
            }
        }
        if (best_idx < 0) break;
        picked[best_idx] = true;
        WifiDeviceStats& d = wifi_stats.devices[best_idx];

        JsonObject dev = top.createNestedObject();
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
        dev["mac"] = mac_str;
        if (d.ssid[0]) dev["ssid"] = d.ssid;
        dev["rssi"] = d.rssi_best;
        dev["frames"] = d.frame_count;
    }

    String json_output;
    serializeJson(doc, json_output);
    Serial.println(json_output);
}

// Buffer a BLE device for verbose output (non-matched devices only)
void verbose_ble_buffer_device(const char* mac, const char* name, int rssi)
{
    if (ble_verbose_buffer.device_count >= VERBOSE_BLE_MAX_DEVICES) return;
    BleDeviceEntry& e = ble_verbose_buffer.devices[ble_verbose_buffer.device_count];
    strncpy(e.mac, mac, 17);
    e.mac[17] = '\0';
    if (name && name[0]) {
        strncpy(e.name, name, 32);
        e.name[32] = '\0';
        e.has_name = true;
    } else {
        e.name[0] = '\0';
        e.has_name = false;
    }
    e.rssi = rssi;
    ble_verbose_buffer.device_count++;
}

// Emit BLE verbose summary JSON after scan completes
void verbose_ble_emit_summary()
{
    if (ble_verbose_buffer.device_count == 0) return;

    DynamicJsonDocument doc(2048);
    doc["type"] = "verbose";
    doc["protocol"] = "bluetooth_le";
    doc["total_devices"] = ble_verbose_buffer.device_count;

    int output_count = min((int)ble_verbose_buffer.device_count, VERBOSE_BLE_OUTPUT_CAP);
    JsonArray devs = doc.createNestedArray("devices");
    for (int i = 0; i < output_count; i++) {
        BleDeviceEntry& e = ble_verbose_buffer.devices[i];
        JsonObject dev = devs.createNestedObject();
        dev["mac"] = e.mac;
        if (e.has_name) dev["name"] = e.name;
        dev["rssi"] = e.rssi;
    }

    String json_output;
    serializeJson(doc, json_output);
    Serial.println(json_output);
}

// ============================================================================
// AUDIO SYSTEM
// ============================================================================

void beep(int frequency, int duration_ms)
{
    tone(BUZZER_PIN, frequency, duration_ms);
    delay(duration_ms + 50);
}

void boot_beep_sequence()
{
    printf("Initializing audio system...\n");
    printf("Playing boot sequence: Low -> High pitch\n");
    beep(LOW_FREQ, BOOT_BEEP_DURATION);
    beep(HIGH_FREQ, BOOT_BEEP_DURATION);
    printf("Audio system ready\n\n");
}

void flock_detected_beep_sequence()
{
    printf("FLOCK SAFETY DEVICE DETECTED!\n");
    printf("Playing alert sequence: 3 fast high-pitch beeps\n");
    for (int i = 0; i < 3; i++) {
        beep(DETECT_FREQ, DETECT_BEEP_DURATION);
        if (i < 2) delay(50); // Short gap between beeps
    }
    printf("Detection complete - device identified!\n\n");
    
    // Mark device as in range and start heartbeat tracking
    device_in_range = true;
    last_detection_time = millis();
    last_heartbeat = millis();
}

void heartbeat_pulse()
{
    printf("Heartbeat: Device still in range\n");
    beep(HEARTBEAT_FREQ, HEARTBEAT_DURATION);
    delay(100);
    beep(HEARTBEAT_FREQ, HEARTBEAT_DURATION);
}

// ============================================================================
// TFT DISPLAY FUNCTIONS
// ============================================================================

#ifdef HAS_TFT
void display_init()
{
    // Power on the TFT and I2C bus
    pinMode(TFT_I2C_POWER, OUTPUT);
    digitalWrite(TFT_I2C_POWER, HIGH);
    delay(10);

    pinMode(TFT_BACKLITE, OUTPUT);
    digitalWrite(TFT_BACKLITE, HIGH);

    tft.init(135, 240);
    tft.setRotation(1);  // Landscape: 240 wide x 135 tall
    tft.fillScreen(ST77XX_BLACK);
}

// Draw a braille dot pattern at (x, y). The pattern byte maps bits to a
// 2-column x 4-row dot grid following the Unicode braille layout.
void draw_braille_spinner(int x, int y, uint8_t pattern, uint16_t color)
{
    const int dot_r = 2;   // dot radius
    const int col_sp = 8;  // horizontal spacing between columns
    const int row_sp = 5;  // vertical spacing between rows
    // bit -> (column, row)
    const int dot_col[] = {0, 0, 0, 1, 1, 1, 0, 1};
    const int dot_row[] = {0, 1, 2, 0, 1, 2, 3, 3};

    // Clear the spinner cell area
    tft.fillRect(x - 1, y - 1, col_sp + dot_r * 2 + 2, row_sp * 3 + dot_r * 2 + 2, ST77XX_BLACK);

    for (int i = 0; i < 8; i++) {
        if (pattern & (1 << i)) {
            int cx = x + dot_col[i] * col_sp + dot_r;
            int cy = y + dot_row[i] * row_sp + dot_r;
            tft.fillCircle(cx, cy, dot_r, color);
        }
    }
}

// Draw or clear the VERBOSE badge in the top-right corner
void display_verbose_badge()
{
    if (verbose_mode) {
        tft.setTextSize(1);
        tft.setTextColor(ST77XX_MAGENTA, ST77XX_BLACK);
        tft.setCursor(190, 2);
        tft.print("VERBOSE");
    } else {
        // Clear the badge area
        tft.fillRect(190, 0, 50, 10, ST77XX_BLACK);
    }
}

void display_scanning_status()
{
    tft.fillScreen(ST77XX_BLACK);

    // Row 1: Title
    tft.setTextSize(2);
    tft.setTextColor(ST77XX_WHITE);
    tft.setCursor(30, 10);
    tft.print("FLOCK SQUAWK");

    // Verbose badge
    display_verbose_badge();

    // Row 2: "SCANNING" + braille spinner
    tft.setTextSize(2);
    tft.setTextColor(ST77XX_GREEN);
    tft.setCursor(36, 50);
    tft.print("SCANNING ");
    draw_braille_spinner(144, 48, spinner_patterns[spinner_frame], ST77XX_GREEN);

    // Row 3: Channel/BLE status
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_CYAN, ST77XX_BLACK);
    tft.setCursor(20, 90);
    char status_line[40];
    snprintf(status_line, sizeof(status_line), "WiFi CH: %02d | BLE: ON", current_channel);
    tft.print(status_line);
}

// Lightweight partial update: only redraws the spinner and channel line
void display_update_scanning_info()
{
    spinner_frame = (spinner_frame + 1) % SPINNER_FRAMES;
    draw_braille_spinner(144, 48, spinner_patterns[spinner_frame], ST77XX_GREEN);

    // Redraw channel line (bg color auto-clears old text)
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_CYAN, ST77XX_BLACK);
    tft.setCursor(20, 90);
    char status_line[40];
    snprintf(status_line, sizeof(status_line), "WiFi CH: %02d | BLE: ON", current_channel);
    tft.print(status_line);

    // Update verbose badge
    display_verbose_badge();
}

void display_detection_alert(int rssi)
{
    // Row 1: Alert title
    tft.setTextSize(2);
    tft.setTextColor(ST77XX_YELLOW);
    tft.setCursor(42, 10);
    tft.print("!! ALERT !!");

    // Verbose badge
    display_verbose_badge();

    // Row 2: Detection text
    tft.setTextSize(2);
    tft.setTextColor(ST77XX_RED);
    tft.setCursor(6, 50);
    tft.print("FLOCK DETECTED");

    // Row 3: Signal strength bar
    int bar_x = 20;
    int bar_y = 90;
    int bar_w = 200;
    int bar_h = 20;

    // Background bar (dark gray)
    tft.fillRect(bar_x, bar_y, bar_w, bar_h, 0x4208);

    // Calculate fill width from RSSI
    int clamped = constrain(rssi, -100, -30);
    int fill_w = map(clamped, -100, -30, 0, bar_w);

    // Color based on signal strength
    uint16_t bar_color;
    if (rssi > -50) {
        bar_color = ST77XX_GREEN;
    } else if (rssi > -70) {
        bar_color = ST77XX_YELLOW;
    } else {
        bar_color = ST77XX_RED;
    }

    if (fill_w > 0) {
        tft.fillRect(bar_x, bar_y, fill_w, bar_h, bar_color);
    }

    // RSSI label below bar
    tft.setTextSize(1);
    tft.setTextColor(ST77XX_WHITE, ST77XX_BLACK);
    tft.setCursor(bar_x, 115);
    char rssi_label[24];
    snprintf(rssi_label, sizeof(rssi_label), "RSSI: %d dBm    ", rssi);
    tft.print(rssi_label);
}
#endif

// ============================================================================
// JSON OUTPUT FUNCTIONS
// ============================================================================

void output_wifi_detection_json(const char* ssid, const uint8_t* mac, int rssi, const char* detection_type)
{
    DynamicJsonDocument doc(2048);

    // Message type tag
    doc["type"] = "detection";

    // Core detection info
    doc["timestamp"] = millis();
    doc["detection_time"] = String(millis() / 1000.0, 3) + "s";
    doc["protocol"] = "wifi";
    doc["detection_method"] = detection_type;
    doc["alert_level"] = "HIGH";
    doc["device_category"] = "FLOCK_SAFETY";
    
    // WiFi specific info
    doc["ssid"] = ssid;
    doc["ssid_length"] = strlen(ssid);
    doc["rssi"] = rssi;
    doc["signal_strength"] = rssi > -50 ? "STRONG" : (rssi > -70 ? "MEDIUM" : "WEAK");
    doc["channel"] = current_channel;
    
    // MAC address info
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", 
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    doc["mac_address"] = mac_str;
    
    char mac_prefix[9];
    snprintf(mac_prefix, sizeof(mac_prefix), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    doc["mac_prefix"] = mac_prefix;
    doc["vendor_oui"] = mac_prefix;
    
    // Detection pattern matching
    bool ssid_match = false;
    bool mac_match = false;
    
    for (int i = 0; i < sizeof(wifi_ssid_patterns)/sizeof(wifi_ssid_patterns[0]); i++) {
        if (strcasestr(ssid, wifi_ssid_patterns[i])) {
            doc["matched_ssid_pattern"] = wifi_ssid_patterns[i];
            doc["ssid_match_confidence"] = "HIGH";
            ssid_match = true;
            break;
        }
    }
    
    for (int i = 0; i < sizeof(mac_prefixes)/sizeof(mac_prefixes[0]); i++) {
        if (strncasecmp(mac_prefix, mac_prefixes[i], 8) == 0) {
            doc["matched_mac_pattern"] = mac_prefixes[i];
            doc["mac_match_confidence"] = "HIGH";
            mac_match = true;
            break;
        }
    }
    
    // Detection summary
    doc["detection_criteria"] = ssid_match && mac_match ? "SSID_AND_MAC" : (ssid_match ? "SSID_ONLY" : "MAC_ONLY");
    doc["threat_score"] = ssid_match && mac_match ? 100 : (ssid_match || mac_match ? 85 : 70);
    
    // Frame type details
    if (strcmp(detection_type, "probe_request") == 0 || strcmp(detection_type, "probe_request_mac") == 0) {
        doc["frame_type"] = "PROBE_REQUEST";
        doc["frame_description"] = "Device actively scanning for networks";
    } else {
        doc["frame_type"] = "BEACON";
        doc["frame_description"] = "Device advertising its network";
    }
    
    String json_output;
    serializeJson(doc, json_output);
    Serial.println(json_output);
}

void output_ble_detection_json(const char* mac, const char* name, int rssi, const char* detection_method)
{
    DynamicJsonDocument doc(2048);

    // Message type tag
    doc["type"] = "detection";

    // Core detection info
    doc["timestamp"] = millis();
    doc["detection_time"] = String(millis() / 1000.0, 3) + "s";
    doc["protocol"] = "bluetooth_le";
    doc["detection_method"] = detection_method;
    doc["alert_level"] = "HIGH";
    doc["device_category"] = "FLOCK_SAFETY";
    
    // BLE specific info
    doc["mac_address"] = mac;
    doc["rssi"] = rssi;
    doc["signal_strength"] = rssi > -50 ? "STRONG" : (rssi > -70 ? "MEDIUM" : "WEAK");
    
    // Device name info
    if (name && strlen(name) > 0) {
        doc["device_name"] = name;
        doc["device_name_length"] = strlen(name);
        doc["has_device_name"] = true;
    } else {
        doc["device_name"] = "";
        doc["device_name_length"] = 0;
        doc["has_device_name"] = false;
    }
    
    // MAC address analysis
    char mac_prefix[9];
    strncpy(mac_prefix, mac, 8);
    mac_prefix[8] = '\0';
    doc["mac_prefix"] = mac_prefix;
    doc["vendor_oui"] = mac_prefix;
    
    // Detection pattern matching
    bool name_match = false;
    bool mac_match = false;
    
    // Check MAC prefix patterns
    for (int i = 0; i < sizeof(mac_prefixes)/sizeof(mac_prefixes[0]); i++) {
        if (strncasecmp(mac, mac_prefixes[i], strlen(mac_prefixes[i])) == 0) {
            doc["matched_mac_pattern"] = mac_prefixes[i];
            doc["mac_match_confidence"] = "HIGH";
            mac_match = true;
            break;
        }
    }
    
    // Check device name patterns
    if (name && strlen(name) > 0) {
        for (int i = 0; i < sizeof(device_name_patterns)/sizeof(device_name_patterns[0]); i++) {
            if (strcasestr(name, device_name_patterns[i])) {
                doc["matched_name_pattern"] = device_name_patterns[i];
                doc["name_match_confidence"] = "HIGH";
                name_match = true;
                break;
            }
        }
    }
    
    // Detection summary
    doc["detection_criteria"] = name_match && mac_match ? "NAME_AND_MAC" : 
                               (name_match ? "NAME_ONLY" : "MAC_ONLY");
    doc["threat_score"] = name_match && mac_match ? 100 : 
                         (name_match || mac_match ? 85 : 70);
    
    // BLE advertisement type analysis
    doc["advertisement_type"] = "BLE_ADVERTISEMENT";
    doc["advertisement_description"] = "Bluetooth Low Energy device advertisement";
    
    // Detection method details
    if (strcmp(detection_method, "mac_prefix") == 0) {
        doc["primary_indicator"] = "MAC_ADDRESS";
        doc["detection_reason"] = "MAC address matches known Flock Safety prefix";
    } else if (strcmp(detection_method, "device_name") == 0) {
        doc["primary_indicator"] = "DEVICE_NAME";
        doc["detection_reason"] = "Device name matches Flock Safety pattern";
    }
    
    String json_output;
    serializeJson(doc, json_output);
    Serial.println(json_output);
}

// ============================================================================
// DETECTION HELPER FUNCTIONS
// ============================================================================

bool check_mac_prefix(const uint8_t* mac)
{
    char mac_str[9];  // Only need first 3 octets for prefix check
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    
    for (int i = 0; i < sizeof(mac_prefixes)/sizeof(mac_prefixes[0]); i++) {
        if (strncasecmp(mac_str, mac_prefixes[i], 8) == 0) {
            return true;
        }
    }
    return false;
}

bool check_ssid_pattern(const char* ssid)
{
    if (!ssid) return false;
    
    for (int i = 0; i < sizeof(wifi_ssid_patterns)/sizeof(wifi_ssid_patterns[0]); i++) {
        if (strcasestr(ssid, wifi_ssid_patterns[i])) {
            return true;
        }
    }
    return false;
}

bool check_device_name_pattern(const char* name)
{
    if (!name) return false;
    
    for (int i = 0; i < sizeof(device_name_patterns)/sizeof(device_name_patterns[0]); i++) {
        if (strcasestr(name, device_name_patterns[i])) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// RAVEN UUID DETECTION
// ============================================================================

// Check if a BLE device advertises any Raven surveillance service UUIDs
bool check_raven_service_uuid(NimBLEAdvertisedDevice* device, char* detected_service_out = nullptr)
{
    if (!device) return false;
    
    // Check if device has service UUIDs
    if (!device->haveServiceUUID()) return false;
    
    // Get the number of service UUIDs
    int serviceCount = device->getServiceUUIDCount();
    if (serviceCount == 0) return false;
    
    // Check each advertised service UUID against known Raven UUIDs
    for (int i = 0; i < serviceCount; i++) {
        NimBLEUUID serviceUUID = device->getServiceUUID(i);
        std::string uuidStr = serviceUUID.toString();
        
        // Compare against each known Raven service UUID
        for (int j = 0; j < sizeof(raven_service_uuids)/sizeof(raven_service_uuids[0]); j++) {
            if (strcasecmp(uuidStr.c_str(), raven_service_uuids[j]) == 0) {
                // Match found! Store the detected service UUID if requested
                if (detected_service_out != nullptr) {
                    strncpy(detected_service_out, uuidStr.c_str(), 40);
                }
                return true;
            }
        }
    }
    
    return false;
}

// Get a human-readable description of the Raven service
const char* get_raven_service_description(const char* uuid)
{
    if (!uuid) return "Unknown Service";
    
    if (strcasecmp(uuid, RAVEN_DEVICE_INFO_SERVICE) == 0)
        return "Device Information (Serial, Model, Firmware)";
    if (strcasecmp(uuid, RAVEN_GPS_SERVICE) == 0)
        return "GPS Location Service (Lat/Lon/Alt)";
    if (strcasecmp(uuid, RAVEN_POWER_SERVICE) == 0)
        return "Power Management (Battery/Solar)";
    if (strcasecmp(uuid, RAVEN_NETWORK_SERVICE) == 0)
        return "Network Status (LTE/WiFi)";
    if (strcasecmp(uuid, RAVEN_UPLOAD_SERVICE) == 0)
        return "Upload Statistics Service";
    if (strcasecmp(uuid, RAVEN_ERROR_SERVICE) == 0)
        return "Error/Failure Tracking Service";
    if (strcasecmp(uuid, RAVEN_OLD_HEALTH_SERVICE) == 0)
        return "Health/Temperature Service (Legacy)";
    if (strcasecmp(uuid, RAVEN_OLD_LOCATION_SERVICE) == 0)
        return "Location Service (Legacy)";
    
    return "Unknown Raven Service";
}

// Estimate firmware version based on detected service UUIDs
const char* estimate_raven_firmware_version(NimBLEAdvertisedDevice* device)
{
    if (!device || !device->haveServiceUUID()) return "Unknown";
    
    bool has_new_gps = false;
    bool has_old_location = false;
    bool has_power_service = false;
    
    int serviceCount = device->getServiceUUIDCount();
    for (int i = 0; i < serviceCount; i++) {
        NimBLEUUID serviceUUID = device->getServiceUUID(i);
        std::string uuidStr = serviceUUID.toString();
        
        if (strcasecmp(uuidStr.c_str(), RAVEN_GPS_SERVICE) == 0)
            has_new_gps = true;
        if (strcasecmp(uuidStr.c_str(), RAVEN_OLD_LOCATION_SERVICE) == 0)
            has_old_location = true;
        if (strcasecmp(uuidStr.c_str(), RAVEN_POWER_SERVICE) == 0)
            has_power_service = true;
    }
    
    // Firmware version heuristics based on service presence
    if (has_old_location && !has_new_gps)
        return "1.1.x (Legacy)";
    if (has_new_gps && !has_power_service)
        return "1.2.x";
    if (has_new_gps && has_power_service)
        return "1.3.x (Latest)";
    
    return "Unknown Version";
}

// ============================================================================
// WIFI PROMISCUOUS MODE HANDLER
// ============================================================================

typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration_id:16;
    uint8_t addr1[6]; /* receiver address */
    uint8_t addr2[6]; /* sender address */
    uint8_t addr3[6]; /* filtering address */
    unsigned sequence_ctrl:16;
    uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // Check for probe requests (subtype 0x04) and beacons (subtype 0x08)
    uint8_t frame_type = (hdr->frame_ctrl & 0xFF) >> 2;
    if (frame_type != 0x20 && frame_type != 0x80) { // Probe request or beacon
        return;
    }

    // Extract SSID from probe request or beacon
    char ssid[33] = {0};
    uint8_t *payload = (uint8_t *)ipkt + 24; // Skip MAC header

    if (frame_type == 0x20) { // Probe request
        payload += 0; // Probe requests start with SSID immediately
    } else { // Beacon frame
        payload += 12; // Skip fixed parameters in beacon
    }

    // Parse SSID element (tag 0, length, data)
    if (payload[0] == 0 && payload[1] <= 32) {
        memcpy(ssid, &payload[2], payload[1]);
        ssid[payload[1]] = '\0';
    }

    // Track frame in verbose stats (always, regardless of match)
    if (verbose_mode) {
        bool is_probe = (frame_type == 0x20);
        verbose_wifi_track_frame(hdr->addr2, ssid, ppkt->rx_ctrl.rssi, is_probe);
    }

    // Check if SSID matches our patterns
    if (strlen(ssid) > 0 && check_ssid_pattern(ssid)) {
        const char* detection_type = (frame_type == 0x20) ? "probe_request" : "beacon";
        output_wifi_detection_json(ssid, hdr->addr2, ppkt->rx_ctrl.rssi, detection_type);
        
        if (!triggered) {
            triggered = true;
            flock_detected_beep_sequence();
        }
        // Always update detection time for heartbeat tracking
        last_detection_time = millis();
#ifdef HAS_TFT
        last_rssi = ppkt->rx_ctrl.rssi;
        display_needs_update = true;
#endif
        return;
    }

    // Check MAC address
    if (check_mac_prefix(hdr->addr2)) {
        const char* detection_type = (frame_type == 0x20) ? "probe_request_mac" : "beacon_mac";
        output_wifi_detection_json(ssid[0] ? ssid : "hidden", hdr->addr2, ppkt->rx_ctrl.rssi, detection_type);
        
        if (!triggered) {
            triggered = true;
            flock_detected_beep_sequence();
        }
        // Always update detection time for heartbeat tracking
        last_detection_time = millis();
#ifdef HAS_TFT
        last_rssi = ppkt->rx_ctrl.rssi;
        display_needs_update = true;
#endif
        return;
    }
}

// ============================================================================
// BLE SCANNING
// ============================================================================

class AdvertisedDeviceCallbacks: public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        
        NimBLEAddress addr = advertisedDevice->getAddress();
        std::string addrStr = addr.toString();
        uint8_t mac[6];
        sscanf(addrStr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", 
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        
        int rssi = advertisedDevice->getRSSI();
        std::string name = "";
        if (advertisedDevice->haveName()) {
            name = advertisedDevice->getName();
        }
        
        // Check MAC prefix
        if (check_mac_prefix(mac)) {
            output_ble_detection_json(addrStr.c_str(), name.c_str(), rssi, "mac_prefix");
            if (!triggered) {
                triggered = true;
                flock_detected_beep_sequence();
            }
            // Always update detection time for heartbeat tracking
            last_detection_time = millis();
#ifdef HAS_TFT
            last_rssi = rssi;
            display_needs_update = true;
#endif
            return;
        }

        // Check device name
        if (!name.empty() && check_device_name_pattern(name.c_str())) {
            output_ble_detection_json(addrStr.c_str(), name.c_str(), rssi, "device_name");
            if (!triggered) {
                triggered = true;
                flock_detected_beep_sequence();
            }
            // Always update detection time for heartbeat tracking
            last_detection_time = millis();
#ifdef HAS_TFT
            last_rssi = rssi;
            display_needs_update = true;
#endif
            return;
        }

        // Check for Raven surveillance device service UUIDs
        char detected_service_uuid[41] = {0};
        if (check_raven_service_uuid(advertisedDevice, detected_service_uuid)) {
            // Raven device detected! Get firmware version estimate
            const char* fw_version = estimate_raven_firmware_version(advertisedDevice);
            const char* service_desc = get_raven_service_description(detected_service_uuid);
            
            // Create enhanced JSON output with Raven-specific data
            StaticJsonDocument<1024> doc;
            doc["type"] = "detection";
            doc["protocol"] = "bluetooth_le";
            doc["detection_method"] = "raven_service_uuid";
            doc["device_type"] = "RAVEN_GUNSHOT_DETECTOR";
            doc["manufacturer"] = "SoundThinking/ShotSpotter";
            doc["mac_address"] = addrStr.c_str();
            doc["rssi"] = rssi;
            doc["signal_strength"] = rssi > -50 ? "STRONG" : (rssi > -70 ? "MEDIUM" : "WEAK");
            
            if (!name.empty()) {
                doc["device_name"] = name.c_str();
            }
            
            // Raven-specific information
            doc["raven_service_uuid"] = detected_service_uuid;
            doc["raven_service_description"] = service_desc;
            doc["raven_firmware_version"] = fw_version;
            doc["threat_level"] = "CRITICAL";
            doc["threat_score"] = 100;
            
            // List all detected service UUIDs
            if (advertisedDevice->haveServiceUUID()) {
                JsonArray services = doc.createNestedArray("service_uuids");
                int serviceCount = advertisedDevice->getServiceUUIDCount();
                for (int i = 0; i < serviceCount; i++) {
                    NimBLEUUID serviceUUID = advertisedDevice->getServiceUUID(i);
                    services.add(serviceUUID.toString().c_str());
                }
            }
            
            // Output the detection
            serializeJson(doc, Serial);
            Serial.println();
            
            if (!triggered) {
                triggered = true;
                flock_detected_beep_sequence();
            }
            // Always update detection time for heartbeat tracking
            last_detection_time = millis();
#ifdef HAS_TFT
            last_rssi = rssi;
            display_needs_update = true;
#endif
            return;
        }

        // No match — buffer for verbose output if enabled
        if (verbose_mode) {
            verbose_ble_buffer_device(addrStr.c_str(), name.c_str(), rssi);
        }
    }
};

// ============================================================================
// CHANNEL HOPPING
// ============================================================================

void hop_channel()
{
    unsigned long now = millis();
    if (now - last_channel_hop > CHANNEL_HOP_INTERVAL) {
        // Emit verbose WiFi summary for the channel we're leaving
        if (verbose_mode) {
            verbose_wifi_emit_summary(current_channel);
            verbose_wifi_stats_reset();
        }

        current_channel++;
        if (current_channel > MAX_CHANNEL) {
            current_channel = 1;
        }
        esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
        last_channel_hop = now;
        printf("[WiFi] Hopped to channel %d\n", current_channel);
#ifdef HAS_TFT
        if (!display_in_alert_mode) {
            display_update_scanning_info();
        }
#endif
    }
}

// ============================================================================
// MAIN FUNCTIONS
// ============================================================================

void setup()
{
    Serial.begin(115200);
    delay(1000);
    
    // Initialize buzzer
    pinMode(BUZZER_PIN, OUTPUT);
    digitalWrite(BUZZER_PIN, LOW);
    boot_beep_sequence();

    // Initialize verbose mode button (GPIO0 / Boot button)
    pinMode(VERBOSE_BUTTON_PIN, INPUT_PULLUP);
    attachInterrupt(digitalPinToInterrupt(VERBOSE_BUTTON_PIN), verbose_button_isr, FALLING);
    verbose_wifi_stats_reset();
    ble_verbose_buffer.device_count = 0;
    verbose_last_reported = verbose_mode;

#ifdef HAS_TFT
    display_init();
    display_scanning_status();
#endif

    printf("Starting Flock Squawk Enhanced Detection System...\n\n");
    
    // Initialize WiFi in promiscuous mode
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    
    printf("WiFi promiscuous mode enabled on channel %d\n", current_channel);
    printf("Monitoring probe requests and beacons...\n");
    
    // Initialize BLE
    printf("Initializing BLE scanner...\n");
    NimBLEDevice::init("");
    pBLEScan = NimBLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);
    
    printf("BLE scanner initialized\n");
    printf("System ready - hunting for Flock Safety devices...\n\n");
    
    last_channel_hop = millis();
}

void loop()
{
    // Check for verbose mode toggle (button ISR sets the flag)
    verbose_check_status_change();

    // Handle channel hopping for WiFi promiscuous mode
    hop_channel();

    // Handle heartbeat pulse if device is in range
    if (device_in_range) {
        unsigned long now = millis();
        
        // Check if 10 seconds have passed since last heartbeat
        if (now - last_heartbeat >= 10000) {
            heartbeat_pulse();
            last_heartbeat = now;
        }
        
        // Check if device has gone out of range (no detection for 30 seconds)
        if (now - last_detection_time >= 30000) {
            printf("Device out of range - stopping heartbeat\n");
            device_in_range = false;
            triggered = false; // Allow new detections
#ifdef HAS_TFT
            display_in_alert_mode = false;
            display_scanning_status();
#endif
        }
    }
    
#ifdef HAS_TFT
    // Update display if needed (throttled)
    if (display_needs_update && (millis() - last_display_update >= DISPLAY_UPDATE_INTERVAL)) {
        if (!display_in_alert_mode) {
            tft.fillScreen(ST77XX_BLACK);
            display_in_alert_mode = true;
        }
        display_detection_alert(last_rssi);
        display_needs_update = false;
        last_display_update = millis();
    }
#endif

    if (millis() - last_ble_scan >= BLE_SCAN_INTERVAL && !pBLEScan->isScanning()) {
        printf("[BLE] scan...\n");
        // Reset verbose BLE buffer before each scan
        ble_verbose_buffer.device_count = 0;
        pBLEScan->start(BLE_SCAN_DURATION, false);
        last_ble_scan = millis();
    }

    if (pBLEScan->isScanning() == false && millis() - last_ble_scan > BLE_SCAN_DURATION * 1000) {
        // Emit verbose BLE summary after scan completes
        if (verbose_mode) {
            verbose_ble_emit_summary();
        }
        pBLEScan->clearResults();
    }
    
    delay(100);
}
