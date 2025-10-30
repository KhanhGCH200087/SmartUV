// 1. Includes
#include <WiFi.h>
#include <ArduinoOTA.h>
#include <WebServer.h>
#include "FS.h"
#include "SD.h"
#include "SPI.h"
#include <SHA1Builder.h>
#include <vector>
#include <algorithm>
#include <string>
#include <ArduinoJson.h>
#include <ThreeWire.h>
#include <RtcDS1302.h>
#include <Ticker.h>

// 2. Defines and constants
#define LIGHT_PIN 17
#define FAN_PIN 16
#define PRESENCE_SENSOR_PIN 22 
#define MODE_SWITCH_PIN 15

// Visual Indicator Pins
#define MODE_0_LED_PIN 32 // Output for Mode 0 (NO)
#define MODE_1_LED_PIN 12 // Output for Mode 1 (NC)
#define MODE_2_LED_PIN 13 // Output for Mode 2 (AUTO)

#define TOTAL_MINUTES_IN_WEEK (7 * 24 * 60)
#define TOTAL_SECONDS_IN_WEEK (7 * 24 * 60 * 60) // Total seconds in a week
#define SECONDS_PER_MINUTE (60)
#define MILLIS_PER_SECOND (1000UL) // Use UL for unsigned long

// Button Timing Constants
#define LOCK_HOLD_TIME_MS 2500UL    // Minimum hold time to lock/unlock
#define MAX_HOLD_TIME_MS 5000UL     // Maximum hold time for valid lock/unlock action
#define UNLOCK_TIMEOUT_MS 30000UL   // Timeout to automatically relock system

#define FAN_FIXED_RUNTIME_MINUTES 3
#define MAX_CYCLE_SUPPORT 5

const char *ssid = "Engine194";
const char *password = "Engine194";
const char *UNAUTHORIZED = "Unauthorized";
const char *INTERNAL_SERVER_ERROR = "Internal server error";
const char *BAD_REQUEST = "Bad request";
const char *NOT_FOUND = "Resource not found";
const char *SUCCESS = "{\"status\": \"ok\"}";
const char *PLAIN_TEXT = "text/plain";
const char *JSON_APPLICATION = "application/json";
const char *CONFIG_ROOT_PATH = "/config/";
const char *AUTH_ROOT_PATH = "/auth/";
const size_t JSON_DOC_SIZE = 1024;

// 3. Global variables
bool current_light_state = false; // Actual state of the Light pin
bool current_fan_state = false;   // Actual state of the Fan pin
bool desired_light_state = false; // State requested by mode/schedule
bool desired_fan_state = false;   // State requested by mode/schedule

// Global variables to store RTC time (updated once in sync_rtc_time)
int rtc_day_of_week = 0; 
int rtc_hour = 0;
int rtc_minute = 0;
int rtc_second = 0; // Global variable for seconds
int timeZone_offset = 420; // in minutes

// Mode Control Variables
// 0=NO (Light OFF), 1=NC (Light ON), 2=AUTO (Run Schedule)
int current_mode = 2; 
bool is_unlocked = false; // System lock state for physical button
unsigned long button_press_start_time = 0;
unsigned long unlock_timestamp = 0;
int last_button_state = HIGH;


Ticker scheduleTicker;
int sck = 18;
int miso = 19;
int mosi = 23;
int cs = 5;
const int IO = 27;
const int SCLK = 14;
const int CE = 26;
ThreeWire myWire(IO, SCLK, CE);
RtcDS1302<ThreeWire> Rtc(myWire);
String secret_token_hex = "5715790a892990382d98858c4aa38d0617151575";
static unsigned char _bearer[20];
WebServer server(80);
char www_username[128] = "admin";

// 4. Structs and type definitions
struct PasswordStruct
{
  const char *value;
  const char *date;
};
struct CycleConfig
{
  std::string start;
  std::string end;
  int status;
  int fan_enable;
  int fan_delay;
  std::vector<int> day;
};
struct ScheduledEvent
{
  // Time is now stored in total seconds since Sunday 00:00 UTC
  int time_of_week_seconds; 
  bool turn_light_on;
  bool fan_change;
  bool fan_state_target;
  int cycle_index;
  bool operator<(const ScheduledEvent &other) const
  {
    return time_of_week_seconds < other.time_of_week_seconds;
  }
};
std::vector<ScheduledEvent> all_events;
std::vector<CycleConfig> activeCycles;

// 5. Function definitions
// --- Visual Indicator Logic ---
void set_mode_indicator(int mode) {
  // Turn off all
  digitalWrite(MODE_0_LED_PIN, LOW);
  digitalWrite(MODE_1_LED_PIN, LOW);
  digitalWrite(MODE_2_LED_PIN, LOW);

  // Turn on the relevant one
  if (mode == 0) {
    digitalWrite(MODE_0_LED_PIN, HIGH);
    Serial.println("Indicator: NO (0) ON");
  } else if (mode == 1) {
    digitalWrite(MODE_1_LED_PIN, HIGH);
    Serial.println("Indicator: NC (1) ON");
  } else if (mode == 2) {
    digitalWrite(MODE_2_LED_PIN, HIGH);
    Serial.println("Indicator: AUTO (2) ON");
  }
}
// --- End Visual Indicator Logic ---

String *check_bearer_or_auth(HTTPAuthMethod mode, String authReq, String params[])
{
  String lcAuthReq = authReq;
  lcAuthReq.toLowerCase();
  if (mode == OTHER_AUTH && (lcAuthReq.startsWith("bearer ")))
  {
    String secret = authReq.substring(7);
    secret.trim();

    uint8_t sha1[20];
    SHA1Builder sha_builder;

    sha_builder.begin();
    sha_builder.add((uint8_t *)secret.c_str(), secret.length());
    sha_builder.calculate();
    sha_builder.getBytes(sha1);

    if (memcmp(_bearer, sha1, sizeof(_bearer)) == 0)
    {
      Serial.println("Bearer token matches");
      return new String("anything non null");
    }
    else
    {
      Serial.println("Bearer token does not match");
    }
  }
  else if (mode == BASIC_AUTH)
  {
    strcpy(www_username, "");
    strcpy(www_username, lcAuthReq.c_str());
    char fileContent[JSON_DOC_SIZE];
    char path[128];
    strcpy(path, AUTH_ROOT_PATH);
    getJsonFromFile(path, fileContent);
    StaticJsonDocument<JSON_DOC_SIZE> doc;
    DeserializationError error = deserializeJson(doc, fileContent);

    // Check for parsing errors
    if (error)
    {
      Serial.print(F("deserializeJson() failed: "));
      Serial.println(error.f_str());
      return NULL;
    }
    PasswordStruct password;
    password.value = doc["passwords"][0]["value"];
    password.date = doc["passwords"][0]["date"];
    if (password.value != NULL && strlen(password.value) != 0)
    {
      bool ret = server.authenticateBasicSHA1((const char *)lcAuthReq.c_str(), password.value);
      if (ret)
      {
        return new String(params[0]);
      }
    }
    else
    {
      return NULL;
    }
  }
  // No auth found
  return NULL;
};

void getTimeISOFormat(char *timeFormat, RtcDateTime *time)
{
  sprintf(timeFormat, "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
          time->Year(),
          time->Month(),
          time->Day(),
          time->Hour(),
          time->Minute(),
          time->Second());
}

bool writeFile(fs::FS &fs, const char *path, const char *message)
{
  Serial.printf("Writing file: %s\n", path);
  bool result = true;

  File file = fs.open(path, FILE_WRITE);
  if (!file)
  {
    Serial.println("Failed to open file for writing");
    return false;
  }
  if (file.print(message))
  {
    Serial.println("File written");
  }
  else
  {
    Serial.println("Write failed");
    result = false;
  }
  file.close();
  return result;
}

void readFile(fs::FS &fs, const char *path, char *result)
{
  Serial.printf("Reading file: %s\n", path);
  File file = fs.open(path);
  if (!file)
  {
    Serial.println("Failed to open file for reading");
    return;
  }
  size_t bytesRead = 0;
  while (file.available())
  {
    result[bytesRead] = (char)file.read();
    bytesRead++;
  }
  result[bytesRead] = '\0'; // Null-terminate the string
  file.close();
}

void getJsonFromFile(char *path, char *fileContent)
{
  strcat(path, www_username);
  strcat(path, ".json");
  readFile(SD, path, fileContent);
};

bool reload_and_reschedule(); // Forward declaration for use in saveModeToSD

// Function to save the current mode (0, 1, or 2) to the SD card config file
bool saveModeToSD(int newMode) {
  char fileContent[JSON_DOC_SIZE] = "";
  char path[128];
  strcpy(path, CONFIG_ROOT_PATH);
  getJsonFromFile(path, fileContent);
  
  StaticJsonDocument<JSON_DOC_SIZE> configDoc;
  DeserializationError error = deserializeJson(configDoc, fileContent);
  
  if (error) {
    Serial.printf("❌ Error reading config to save mode: %s\n", error.c_str());
    return false;
  }
  
  configDoc["mode"] = newMode;
  serializeJson(configDoc, fileContent);
  
  bool success = writeFile(SD, path, fileContent);
  if (success) {
      current_mode = newMode;
      set_mode_indicator(current_mode); // Update indicator immediately
      Serial.printf("✅ Saved new mode (%d) to SD card and applied.\n", newMode);
      // Force a reschedule to immediately apply the new mode logic
      reload_and_reschedule(); 
  } else {
      Serial.println("❌ Failed to save mode to SD card.");
  }
  return success;
}

bool loadConfigFromSD(std::vector<CycleConfig> &cycles)
{
  char fileContent[JSON_DOC_SIZE];
  char path[128];
  strcpy(path, CONFIG_ROOT_PATH);
  getJsonFromFile(path, fileContent);
  // Parse JSON
  StaticJsonDocument<JSON_DOC_SIZE> doc;
  DeserializationError error = deserializeJson(doc, fileContent);
  if (error)
  {
    Serial.printf("❌ JSON parsing error: %s\n", error.c_str());
    return false;
  }

  // Get TimeZone Offset
  if (doc["timeZone"].is<int>())
  {
    timeZone_offset = doc["timeZone"].as<int>();
  }
  else
  {
    timeZone_offset = 420; // Default to UTC+7 if not found or invalid
    Serial.println("Warning: timeZone not found in config. Using default UTC+7.");
  }
  
  // Get Mode (New Feature)
  if (doc["mode"].is<int>())
  {
    current_mode = doc["mode"].as<int>();
  }
  else
  {
    current_mode = 2; // Default to AUTO
    Serial.println("Warning: mode not found in config. Using default AUTO (2).");
  }
  set_mode_indicator(current_mode); // Update indicator after loading mode

  // Get the "cycles" array
  JsonArray jsonCycles = doc["cycles"].as<JsonArray>();
  if (jsonCycles.isNull())
  {
    Serial.println("❌ Error: 'cycles' array not found in JSON.");
    return false;
  }

  // Convert from JsonArray to std::vector<CycleConfig>
  for (JsonObject jsonCycle : jsonCycles)
  {
    CycleConfig cycle;
    cycle.start = jsonCycle["start"].as<const char*>();
    cycle.end = jsonCycle["end"].as<const char*>();
    cycle.status = jsonCycle["status"].as<int>();
    cycle.fan_enable = jsonCycle["fan_enable"].as<int>();
    cycle.fan_delay = jsonCycle["fan_delay"].as<int>();

    JsonArray dayArray = jsonCycle["day"].as<JsonArray>();
    for (int dayValue : dayArray)
    {
      cycle.day.push_back(dayValue);
    }
    // Only add if configuration is enabled
    if (cycle.status == 1)
    {
      cycles.push_back(cycle);
    }
  }
  Serial.printf("✅ JSON read successful. Loaded %zu active cycles into RAM. TimeZone Offset: %d minutes. Mode: %d\n", cycles.size(), timeZone_offset, current_mode);
  return true;
}

// RTC time synchronization function. Fetches time from the module once and stores it in global variables.
void sync_rtc_time()
{
  RtcDateTime now = Rtc.GetDateTime();
  if (now.IsValid())
  {
    rtc_day_of_week = now.DayOfWeek();
    rtc_hour = now.Hour();
    rtc_minute = now.Minute();
    rtc_second = now.Second(); // Fetch second and store it in the global variable
  } else {
    Serial.println("RTC time is invalid, cannot sync.");
  }
}

// Function to calculate total seconds elapsed since Sunday 00:00 (Uses global variables to avoid latency)
int get_current_time_of_week_seconds()
{
  // 1. Calculate UTC seconds since the start of the week (00:00 Sunday UTC)
  // RtcDateTime::DayOfWeek() returns 0 for Sunday, 1 for Monday, ..., 6 for Saturday.
  unsigned long utc_seconds = rtc_day_of_week * 24 * 60 * 60 + 
                              rtc_hour * 60 * 60 + 
                              rtc_minute * 60 + 
                              rtc_second; // USE GLOBAL VARIABLE

  // 2. Apply local time offset
  int offset_seconds = timeZone_offset * 60;
  long local_seconds = (long)utc_seconds + offset_seconds; // Use long to prevent overflow

  // 3. Ensure the result is within the range of one week
  int seconds_in_week = local_seconds % TOTAL_SECONDS_IN_WEEK;
  if (seconds_in_week < 0)
  {
    seconds_in_week += TOTAL_SECONDS_IN_WEEK; 
  }
  return seconds_in_week;
}

// Function to update the actual hardware state
void set_light_state(bool light_on, bool fan_on, bool is_overriding)
{
  bool light_changed = (current_light_state != light_on);
  bool fan_changed = (current_fan_state != fan_on);
  
  if (light_changed)
  {
    digitalWrite(LIGHT_PIN, light_on ? HIGH : LOW);
    current_light_state = light_on;
  }
  if (fan_changed)
  {
    digitalWrite(FAN_PIN, fan_on ? HIGH : LOW);
    current_fan_state = fan_on;
  }
  
  if (light_changed || fan_changed) {
      // Get current time (already synced in sync_rtc_time) for logging purposes
      int total_seconds = get_current_time_of_week_seconds();
      int local_day = (total_seconds / (24 * 60 * 60));
      int remaining_seconds = total_seconds % (24 * 60 * 60);
      int local_hour = remaining_seconds / (60 * 60);
      int local_minute = (remaining_seconds % (60 * 60)) / 60;
      int local_second = remaining_seconds % 60;

      const char* mode_name = (current_mode == 0) ? "NO" : (current_mode == 1 ? "NC" : "AUTO");
      const char* event_type = is_overriding ? "OVERRIDE" : "EVENT";

      Serial.printf("--- %s! Day%d %02d:%02d:%02d (Local), Mode: %s. Light: %s, Fan: %s ---\n", 
                    event_type,
                    local_day + 1, local_hour, local_minute, local_second,
                    mode_name,
                    current_light_state ? "ON" : "OFF",
                    current_fan_state ? "ON" : "OFF");
  }
}

void preprocess_config(const std::vector<CycleConfig> &cycles)
{
  all_events.clear();

  // Helper to convert HH:MM string to seconds since 00:00
  auto time_to_seconds = [](const std::string &time_str) -> int
  {
    int h = std::stoi(time_str.substr(0, 2));
    int m = std::stoi(time_str.substr(3, 2));
    return h * 3600 + m * 60;
  };
  
  // Total seconds in one day
  const int SECONDS_PER_DAY = 24 * 60 * 60; 

  for (size_t i = 0; i < cycles.size(); ++i)
  {
    const auto &cycle = cycles[i];

    int start_seconds_in_day = time_to_seconds(cycle.start);
    int end_seconds_in_day = time_to_seconds(cycle.end);
    
    // Total fan run time in seconds
    const int FAN_FIXED_RUNTIME_SECONDS = FAN_FIXED_RUNTIME_MINUTES * 60;

    for (int day_index = 0; day_index < 7; ++day_index)
    {
      if (cycle.day[day_index] == 1)
      {
        int turn_on_time_seconds;
        int turn_off_time_seconds;

        // Calculate event times
        if (start_seconds_in_day < end_seconds_in_day)
        {
          // Cycle starts and ends on the same day
          turn_on_time_seconds = day_index * SECONDS_PER_DAY + start_seconds_in_day;
          turn_off_time_seconds = day_index * SECONDS_PER_DAY + end_seconds_in_day;
        }
        else // Cycle spans midnight
        {
          int next_day_index = (day_index + 1) % 7;
          turn_on_time_seconds = day_index * SECONDS_PER_DAY + start_seconds_in_day;
          turn_off_time_seconds = next_day_index * SECONDS_PER_DAY + end_seconds_in_day;
        }

        // Event 1: Light ON (start of cycle)
        all_events.push_back({turn_on_time_seconds, true, false, false, (int)i});

        // Event 2: Light OFF (end of cycle)
        all_events.push_back({turn_off_time_seconds, false, false, false, (int)i});

        if (cycle.fan_enable)
        {
          // Event 3: Delayed Fan ON. 
          int fan_delay_seconds = cycle.fan_delay * 60;
          int fan_on_delay_time = turn_off_time_seconds + fan_delay_seconds;
          all_events.push_back({fan_on_delay_time, false, true, true, (int)i});

          // Event 4: Fan OFF (After 3 minutes runtime). 
          int fan_off_runtime_end_time = fan_on_delay_time + FAN_FIXED_RUNTIME_SECONDS;
          all_events.push_back({fan_off_runtime_end_time, false, true, false, (int)i});
        }
      }
    }
  }

  std::sort(all_events.begin(), all_events.end());
  Serial.printf("✅ Pre-processing successful: Created %zu scheduled events (in seconds).\n", all_events.size());
}

// Function to calculate the DESIRED state based on mode/schedule and set the next Ticker.
void determine_and_schedule_next_state()
{
  sync_rtc_time(); // Optimization: Access RTC only once here

  // Reset desired states
  desired_light_state = false;
  desired_fan_state = false;
  int now_seconds = get_current_time_of_week_seconds(); 
  
  if (current_mode == 2 && !all_events.empty())
  {
    // --- STEP 1: DETERMINE DESIRED STATE BASED ON SCHEDULE (AUTO MODE) ---
    
    // Loop through sorted events to find the last elapsed event
    for (const auto &event : all_events)
    {
      if (event.time_of_week_seconds <= now_seconds)
      {
        if (!event.fan_change)
        {
          // Light ON/OFF event
          desired_light_state = event.turn_light_on;
          
          // Rule: If light is ON, desired fan must be OFF.
          if (desired_light_state)
          {
            desired_fan_state = false;
          }
        }
        else if (!desired_light_state) // Fan event only applies when Light is OFF
        {
          desired_fan_state = event.fan_state_target;
        }
      }
      else
      {
        break; // Events are sorted, stop searching
      }
    }

    // Final check for schedule: If light is ON, fan must be OFF
    if (desired_light_state)
    {
      desired_fan_state = false;
    }
  }

  // --- STEP 1.5: APPLY MODE OVERRIDE TO DESIRED STATE ---
  if (current_mode == 0) // NO mode (Always OFF)
  {
      desired_light_state = false;
      desired_fan_state = false;
  }
  else if (current_mode == 1) // NC mode (Always ON)
  {
      desired_light_state = true;
      desired_fan_state = false; // Fan is also forced OFF in NC mode
  }
  // If current_mode == 2 (AUTO), desired state from schedule is used.

  // --- STEP 2: FIND AND SCHEDULE NEXT EVENT ---

  // Always detach the current Ticker before setting a new schedule.
  scheduleTicker.detach(); 

  if (current_mode == 2 && !all_events.empty()) 
  {
      // Mode AUTO: Search and schedule the next event
      
      // Find the next event (the first event with time greater than now_seconds)
      auto next_it = std::upper_bound(all_events.begin(), all_events.end(),
                                      ScheduledEvent{now_seconds, false, false, false, 0});

      int next_event_time_seconds;

      if (next_it == all_events.end())
      {
        // If week ends, loop back to the first event of the next week
        next_it = all_events.begin();
        next_event_time_seconds = next_it->time_of_week_seconds + TOTAL_SECONDS_IN_WEEK;
      }
      else
      {
        next_event_time_seconds = next_it->time_of_week_seconds;
      }

      // Calculate precise delay in seconds
      long time_to_next_check_seconds = (long)next_event_time_seconds - (long)now_seconds;

      // Handle rare case if delay <= 0 (should be 1 second)
      if (time_to_next_check_seconds <= 0)
      {
        time_to_next_check_seconds = 1;
      }
      
      int next_day = (next_event_time_seconds / (24 * 60 * 60));
      int next_remaining_seconds = next_event_time_seconds % (24 * 60 * 60);
      int next_hour = next_remaining_seconds / 3600;
      int next_minute = (next_remaining_seconds % 3600) / 60;
      int next_second = next_remaining_seconds % 60;

      Serial.printf(">> Next scheduled event: Day%d %02d:%02d:%02d\n",
                    (next_day % 7) + 1, next_hour, next_minute, next_second);
      
      
      // Set Ticker for the next event
      unsigned long final_delay_ms = (unsigned long)time_to_next_check_seconds * MILLIS_PER_SECOND;

      // Safety check: ensure delay is reasonable
      if (final_delay_ms > (unsigned long)TOTAL_SECONDS_IN_WEEK * MILLIS_PER_SECOND || final_delay_ms == 0) {
          Serial.println("Warning: Calculated delay is invalid. Ticker remains detached.");
          return; 
      }

      scheduleTicker.once_ms(final_delay_ms, determine_and_schedule_next_state);

      Serial.printf(">> Ticker set for: %lu ms (Approx %d sec)\n",
                    final_delay_ms,
                    (int)(final_delay_ms / MILLIS_PER_SECOND));
  } else {
    // Mode 0 (NO), Mode 1 (NC), or Mode 2 with no cycles.
    const char* reason = (current_mode != 2) ? "Mode is NO (0) or NC (1)" : "No active cycles found";
    Serial.printf(">> Ticker remains detached. Reason: %s.\n", reason);
  }
}

// Hàm cập nhật: Chỉ ghi đè trạng thái đèn khi phát hiện người. 
// Trạng thái quạt được giữ nguyên theo lịch trình (desired_fan_state).
void apply_hardware_state() {
    bool final_light_state = desired_light_state;
    bool final_fan_state = desired_fan_state; // Keep fan state according to schedule
    bool is_overriding = false;

    // Read presence sensor state
    int presence_state = digitalRead(PRESENCE_SENSOR_PIN);
    
    // Override logic only for LIGHT: Applies in NC (1) or AUTO (2) mode
    // If light needs to be ON (desired_light_state == true) 
    // AND person detected (presence_state == HIGH)
    if ((current_mode == 1 || current_mode == 2) && desired_light_state == true && presence_state == HIGH) {
        final_light_state = false; // Force Light OFF (Override Light OFF)
        is_overriding = true;
        
        // Log if light is ON and about to be turned OFF
        if (current_light_state != final_light_state) {
            Serial.println("🛑 PRESENCE OVERRIDE: Detected person, forcing Light OFF. Fan logic unchanged.");
        }
    }
    
    // Apply final state to hardware
    // Light: May be overridden.
    // Fan: Follows desired state from schedule/mode.
    set_light_state(final_light_state, final_fan_state, is_overriding);

    // No need to reset Ticker here.
}


// Function to handle the physical button logic for lock/unlock and mode change
void handle_mode_button() {
  int button_state = digitalRead(MODE_SWITCH_PIN);
  unsigned long current_time = millis();

  // 1. Check for unlock timeout
  if (is_unlocked && (current_time - unlock_timestamp > UNLOCK_TIMEOUT_MS)) {
    is_unlocked = false;
    Serial.println("🔒 System locked due to 30 second timeout.");
  }

  // 2. Button Press Logic
  // Simple state check (a more robust debounce could be added, but this is a start)
  if (button_state != last_button_state) {
    // A small delay for simple debouncing before processing the change
    delay(50); 
    button_state = digitalRead(MODE_SWITCH_PIN);
    
    if (button_state == LOW && last_button_state == HIGH) {
      // Button JUST PRESSED (Start of press)
      button_press_start_time = current_time;

    } else if (button_state == HIGH && last_button_state == LOW) {
      // Button JUST RELEASED (End of press)
      unsigned long press_duration = current_time - button_press_start_time;
      
      if (press_duration >= LOCK_HOLD_TIME_MS && press_duration <= MAX_HOLD_TIME_MS) {
        // LONG PRESS (2.5s - 5s): Toggle Lock State
        is_unlocked = !is_unlocked;
        unlock_timestamp = current_time; // Reset timeout on lock/unlock action
        Serial.printf("🔓/🔒 System is now %s. Timeout reset.\n", is_unlocked ? "UNLOCKED" : "LOCKED");
      }
      else if (press_duration < LOCK_HOLD_TIME_MS && press_duration > 50) {
        // SHORT PRESS (Mode Change attempt) (min 50ms to ignore noise)
        if (is_unlocked) {
          // Cycle mode: 2(AUTO) -> 1(NC) -> 0(NO) -> 2(AUTO)
          int new_mode = (current_mode == 2) ? 1 : (current_mode == 1 ? 0 : 2);
          
          if (saveModeToSD(new_mode)) { // saveModeToSD handles persistence and indicator update
            unlock_timestamp = current_time; // Reset timeout on action
            Serial.printf("🔄 Mode changed to %d. Timeout reset.\n", new_mode);
          } else {
             Serial.println("❌ Failed to save new mode. Mode not changed.");
          }
        } else {
          Serial.println("Button press ignored: System is locked.");
        }
      }
      // If press_duration > MAX_HOLD_TIME_MS, it's ignored/failed action.
      button_press_start_time = 0; // Reset press timer
    }
  }

  last_button_state = button_state;
}


// ⚠️ REAL-TIME UPDATE FUNCTION: This is the function you need to call
// after successfully writing a new config.json to the SD card.
bool reload_and_reschedule()
{
  sync_rtc_time(); // Sync time before checking

  if (rtc_day_of_week >= 0) // Simpler validity check
  {
    Serial.println("\n*** Reloading Configuration and Rescheduling ***");

    // 1. Cancel the current schedule immediately
    scheduleTicker.detach();
    Serial.println("  - Old Ticker detached.");

    // 2. Clear previous configuration and events
    activeCycles.clear();
    all_events.clear();

    // 3. Load the new configuration from SD (Updates timeZone_offset and current_mode)
    if (loadConfigFromSD(activeCycles))
    {
      // 4. Pre-process the new cycles into scheduled events (Only needed if in AUTO mode)
      if (current_mode == 2) {
        preprocess_config(activeCycles);
        Serial.printf("Number of items in all_events: %zu (Processed)\n", all_events.size());
      } else {
        Serial.println("Mode is not AUTO (2). Skipping schedule pre-processing.");
      }

      // 5. Immediately check the current DESIRED state and set the new Ticker schedule
      determine_and_schedule_next_state();
      // 6. Apply the newly calculated desired state to hardware (with possible presence override)
      apply_hardware_state();
      Serial.println("  - New schedule successfully initialized.");
      return true;
    }
    else
    {
      // Handle error: if config fails to load, ensure devices are off.
      Serial.println("  - Failed to load config. Devices OFF.");
      set_light_state(false, false, false); // Turn off devices on error
      return false;
    }
  }
  else
  {
    // Handle error: if RTC time is invalid, ensure devices are off.
    Serial.println("  - Failed to get current time. Devices OFF.");
    set_light_state(false, false, false); // Turn off devices on error
    return false;
  }
}

// 6. setup() and loop() at the end
void setup()
{
  Serial.begin(115200);
  pinMode(LIGHT_PIN, OUTPUT);
  pinMode(FAN_PIN, OUTPUT);
  pinMode(MODE_SWITCH_PIN, INPUT_PULLUP);
  pinMode(PRESENCE_SENSOR_PIN, INPUT_PULLDOWN);

  // Setup Visual Indicator Pins
  pinMode(MODE_0_LED_PIN, OUTPUT);
  pinMode(MODE_1_LED_PIN, OUTPUT);
  pinMode(MODE_2_LED_PIN, OUTPUT);

  digitalWrite(LIGHT_PIN, LOW);
  digitalWrite(FAN_PIN, LOW);
  current_light_state = false;
  current_fan_state = false;
  set_mode_indicator(-1); // Turn off all indicators initially

  SPI.begin(sck, miso, mosi, cs);
  if (!SD.begin())
  {
    Serial.println("Card Mount Failed");
    return;
  }
  if (!WiFi.softAP(ssid, password))
  {
    log_e("Soft AP creation failed.");
    while (1)
      ;
  }
  Rtc.Begin();
  IPAddress myIP = WiFi.softAPIP();
  ArduinoOTA.begin();

  // Convert token to a convenient binary representation.
  size_t len = HEXBuilder::hex2bytes(_bearer, sizeof(_bearer), secret_token_hex);
  if (len != 20)
  {
    Serial.println("Bearer token does not look like a valid SHA1 hex string ?!");
  }

  server.on("/config", HTTP_GET, []()
            {
    Serial.println("[/config] - GET - start");
    if (!server.authenticate(&check_bearer_or_auth)) {
      Serial.println("No/failed authentication");
      return server.send(401, PLAIN_TEXT, UNAUTHORIZED);
    }
    char fileContent[JSON_DOC_SIZE] = "";
    char path[128];
    strcpy(path, CONFIG_ROOT_PATH);
    getJsonFromFile(path, fileContent);
    Serial.println("[/config] - GET - return");
    return server.send(200, JSON_APPLICATION, fileContent); });

  // Get present time
  server.on("/time", HTTP_GET, []()
            {
    DynamicJsonDocument doc(100);
    if (!Rtc.GetIsRunning()) {
      Serial.println("RTC was not actively running, starting now");
      Rtc.SetIsRunning(true);
    }
    if (Rtc.GetIsWriteProtected()) {
      Rtc.SetIsWriteProtected(false);
    }
    RtcDateTime now = Rtc.GetDateTime();
    if (now.IsValid()) {
      char str[25];
      getTimeISOFormat(str, &now);
      doc["time"] = str;
    } else {
      doc["time"] = "";
    }
    char fileContent[JSON_DOC_SIZE] = "";
    char path[128];
    strcpy(path, CONFIG_ROOT_PATH);
    getJsonFromFile(path, fileContent);
    StaticJsonDocument<JSON_DOC_SIZE> configDoc;
    DeserializationError error = deserializeJson(configDoc, fileContent);
    if (error)
    {
      Serial.print(F("deserializeJson() config failed: "));
      Serial.println(error.f_str());
      return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
    }
    doc["timeZone"] = configDoc["timeZone"];
    char time_json[100];
    serializeJson(doc, time_json);
    server.send(200, JSON_APPLICATION, time_json); });

  server.on("/time", HTTP_POST, [&]()
            {
    if (!server.authenticate(&check_bearer_or_auth)) {
      Serial.println("No/failed authentication");
      return server.send(401, PLAIN_TEXT, UNAUTHORIZED);
    }
    String requestBody = server.arg("plain");
    StaticJsonDocument<JSON_DOC_SIZE> doc;
    DeserializationError error = deserializeJson(doc, requestBody);
    // Check for parsing errors
    if (error) {
      Serial.print(F("deserializeJson() request body failed: "));
      Serial.println(error.f_str());
      return server.send(400, PLAIN_TEXT, BAD_REQUEST);
    }
    if (!Rtc.GetIsRunning()) {
      Serial.println("RTC was not actively running, starting now");
      Rtc.SetIsRunning(true);
    }
    if (Rtc.GetIsWriteProtected()) {
      Rtc.SetIsWriteProtected(false);
    }
    // doc = {"year": 2025, "month": 1, "day" : 3, "hour": 2, "minute": 34, "second": 0, "timeZone": 420}
    RtcDateTime newTime(
      doc["year"], doc["month"], doc["day"], doc["hour"], doc["minute"], doc["second"]
    );
    Rtc.SetDateTime(newTime);
    
    // Update: Save new TimeZone to config file
    char fileContent[JSON_DOC_SIZE] = "";
    char path[128];
    strcpy(path, CONFIG_ROOT_PATH);
    getJsonFromFile(path, fileContent);
    StaticJsonDocument<JSON_DOC_SIZE> configDoc;
    error = deserializeJson(configDoc, fileContent);
    if (error)
    {
      Serial.print(F("deserializeJson() config failed: "));
      Serial.println(error.f_str());
      return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
    }
    
    // Overwrite the new TimeZone
    if (doc["timeZone"].is<int>()) {
        configDoc["timeZone"] = doc["timeZone"].as<int>();
    }

    serializeJson(configDoc, fileContent);
    bool success = writeFile(SD, path, fileContent);
    if (!success)
    {
      return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
    }
    
    // Reload config and reschedule to apply the new TimeZone immediately
    reload_and_reschedule();
    
    RtcDateTime now = Rtc.GetDateTime();
    if(now.IsValid()){
      char str[32];
      getTimeISOFormat(str, &now);
      char response[64];
      sprintf(response, "{\"time\":\"%s\", \"timeZone\": %d}", str, timeZone_offset);
      return server.send(200, JSON_APPLICATION, response);
    }
    return server.send(400, PLAIN_TEXT, BAD_REQUEST); });
    
  // New API endpoint to set mode (0, 1, or 2) from web interface
  server.on("/mode", HTTP_POST, []() {
    if (!server.authenticate(&check_bearer_or_auth)) {
      Serial.println("No/failed authentication");
      return server.send(401, PLAIN_TEXT, UNAUTHORIZED);
    }
    String requestBody = server.arg("plain");
    StaticJsonDocument<100> doc;
    DeserializationError error = deserializeJson(doc, requestBody);
    if (error || !doc["mode"].is<int>()) {
      Serial.print("Invalid JSON or missing 'mode' field: ");
      Serial.println(error.f_str());
      return server.send(400, PLAIN_TEXT, BAD_REQUEST);
    }
    int new_mode = doc["mode"].as<int>();
    if (new_mode >= 0 && new_mode <= 2) {
      if (saveModeToSD(new_mode)) { // saveModeToSD handles persistence and indicator update
        char response[50];
        sprintf(response, "{\"status\":\"ok\", \"mode\": %d}", new_mode);
        return server.send(200, JSON_APPLICATION, response);
      } else {
        return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
      }
    } else {
      return server.send(400, PLAIN_TEXT, "Mode must be 0, 1, or 2.");
    }
  });


  server.on("/cycles", HTTP_POST, []()
            {
    if (!server.authenticate(&check_bearer_or_auth)) {
      Serial.println("No/failed authentication");
      return server.send(401, PLAIN_TEXT, UNAUTHORIZED);
    }
    String requestBody = server.arg("plain");
    if (requestBody == NULL || requestBody.isEmpty())
    {
      return server.send(400, PLAIN_TEXT, BAD_REQUEST);
    }
    StaticJsonDocument<128> doc;
    DeserializationError error = deserializeJson(doc, requestBody);
    if (error)
    {
      Serial.print(F("deserializeJson() request body failed: "));
      Serial.println(error.f_str());
      return server.send(400, PLAIN_TEXT, BAD_REQUEST);
    }
    char fileContent[JSON_DOC_SIZE] = "";
    char path[128];
    strcpy(path, CONFIG_ROOT_PATH);
    getJsonFromFile(path, fileContent);
    StaticJsonDocument<JSON_DOC_SIZE> configDoc;
    error = deserializeJson(configDoc, fileContent);
    if (error)
    {
      Serial.print(F("deserializeJson() config failed: "));
      Serial.println(error.f_str());
      return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
    }
    int currentCounter = configDoc["cycle_counter"];
    int nextCounter = currentCounter + 1;
    configDoc["cycle_counter"] = nextCounter;
    JsonArray cycles = configDoc["cycles"].as<JsonArray>();
    if (cycles.size() < MAX_CYCLE_SUPPORT)
    {
      JsonObject newCycle = cycles.createNestedObject();
      newCycle["id"] = nextCounter;
      newCycle["status"] = doc["status"];
      newCycle["start"] = doc["start"];
      newCycle["end"] = doc["end"];
      JsonArray newDay = newCycle.createNestedArray("day");
      newDay.set(doc["day"].as<JsonArray>());
      newCycle["fan_enable"] = doc["fan_enable"];
      newCycle["fan_delay"] = doc["fan_delay"];
      serializeJson(configDoc, fileContent);
      bool success = writeFile(SD, path, fileContent);
      if (!success)
      {
        return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
      }
      reload_and_reschedule();
      serializeJson(newCycle, fileContent);
      return server.send(200, JSON_APPLICATION, fileContent);
    }
    return server.send(400, PLAIN_TEXT, BAD_REQUEST); });

  server.on("/cycles", HTTP_PUT, []()
            {
    if (!server.authenticate(&check_bearer_or_auth)) {
      Serial.println("No/failed authentication");
      return server.send(401, PLAIN_TEXT, UNAUTHORIZED);
    }
    String requestBody = server.arg("plain");
    if (requestBody == NULL || requestBody.isEmpty()) {
      return server.send(400, PLAIN_TEXT, BAD_REQUEST);
    }
    StaticJsonDocument<128> doc;
    DeserializationError error = deserializeJson(doc, requestBody);
    if (error || !doc["id"]) {
      if (error) {
        Serial.print(F("deserializeJson() request body failed: "));
        Serial.println(error.f_str());
      }
      return server.send(400, PLAIN_TEXT, BAD_REQUEST);
    }
    char fileContent[JSON_DOC_SIZE] = "";
    char path[128];
    strcpy(path, CONFIG_ROOT_PATH);
    getJsonFromFile(path, fileContent);
    StaticJsonDocument<JSON_DOC_SIZE> configDoc;
    error = deserializeJson(configDoc, fileContent);
    if (error) {
      Serial.print(F("deserializeJson() config failed: "));
      Serial.println(error.f_str());
      return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
    }
    JsonArray cycles = configDoc["cycles"].as<JsonArray>();
    for (int i = 0; i < cycles.size(); i++) {
      JsonObject cycle = cycles[i].as<JsonObject>();
      if (cycle["id"] != doc["id"]) {
        continue;
      } else {
        cycle["status"] = doc["status"];
        cycle["start"] = doc["start"];
        cycle["end"] = doc["end"];
        JsonArray updatedDay = cycle["day"].as<JsonArray>();
        updatedDay.set(doc["day"].as<JsonArray>());
        cycle["fan_enable"] = doc["fan_enable"];
        cycle["fan_delay"] = doc["fan_delay"];
        serializeJson(configDoc, fileContent);
        bool success = writeFile(SD, path, fileContent);
        if (!success) {
          return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
        }
        reload_and_reschedule();
        serializeJson(cycle, fileContent);
        return server.send(200, JSON_APPLICATION, fileContent);
      }
    }
    return server.send(404, PLAIN_TEXT, NOT_FOUND); });

  server.on("/cycles", HTTP_DELETE, []()
            {
    if (!server.authenticate(&check_bearer_or_auth)) {
      Serial.println("No/failed authentication");
      return server.send(401, PLAIN_TEXT, UNAUTHORIZED);
    }
    String requestId = server.arg("id");
    if (requestId == NULL || requestId.isEmpty()) {
      return server.send(400, PLAIN_TEXT, BAD_REQUEST);
    }
    std::string idString = requestId.c_str(); 
    char fileContent[JSON_DOC_SIZE] = "";
    char path[128];
    strcpy(path, CONFIG_ROOT_PATH);
    getJsonFromFile(path, fileContent);
    StaticJsonDocument<JSON_DOC_SIZE> configDoc;
    DeserializationError error = deserializeJson(configDoc, fileContent);
    if (error) {
      Serial.print(F("deserializeJson() config failed: "));
      Serial.println(error.f_str());
      return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
    }
    JsonArray cycles = configDoc["cycles"].as<JsonArray>();
    for (int i = 0; i < cycles.size(); i++) {
      JsonObject cycle = cycles[i].as<JsonObject>();
      if (cycle["id"] != std::__cxx11::stoi(idString)) {
        continue;
      } else {
        cycles.remove(i);
        serializeJson(configDoc, fileContent);
        bool success = writeFile(SD, path, fileContent);
        if (!success) {
          return server.send(500, PLAIN_TEXT, INTERNAL_SERVER_ERROR);
        }
        char response[32];
        reload_and_reschedule();
        sprintf(response, "{\"id\":%s}",requestId.c_str());
        return server.send(200, JSON_APPLICATION ,response);
      }
    }
    return server.send(404, PLAIN_TEXT, NOT_FOUND); });

  server.on("/", HTTP_GET, []()
            {
      if (!server.authenticate(&check_bearer_or_auth)) {
        Serial.println("No/failed authentication");
        return server.requestAuthentication();
      }
      Serial.println("Authentication succeeded");
      File file = SD.open("/ui/index.html", "r");
      if (file) {
          server.streamFile(file, "text/html");
          file.close();
      } else {
          server.send(404, PLAIN_TEXT, NOT_FOUND);
      } });

  server.serveStatic("/", SD, "/ui/");
  server.begin();

  Serial.print("Open http://");
  Serial.print(myIP);
  Serial.println("/ in your browser to see it working");
  reload_and_reschedule();
}

void loop()
{
  ArduinoOTA.handle();
  server.handleClient();
  handle_mode_button(); // Check the physical button logic
  apply_hardware_state(); // Check presence sensor and apply the final state frequently
  delay(10); // allow the cpu to switch to other tasks
}
