// s60sc 2020 - 2025
// RjSachse 2025
#include "appGlobals.h"
#if INCLUDE_ONVIF
#include "onvif.h"

#define ONVIF_PORT 3702 // Onvif Port
#define ONVIF_IP "239.255.255.250" // Onvif listen adress
#define ONVIF_HELLO_INTERVAL 30 // How many secounds to send a udp hello packet for onvif clients
#define ONVIF_BUFFER_SIZE (1024 * 8) // Buffer size to hold responses in.

// Name for varibles that can change in webserver
char onvifManufacturer[16] = "XenoioneX";
char onvifModel[16] = "esp32s3";

// Access Point MAC Address
char apMac[18] = {0};
char staMac[18] = {0};

// Buffer and handles
TaskHandle_t onvifHandle = NULL;
uint8_t* onvifBuffer = NULL;
esp_timer_handle_t helloTimer;

// Global Varibals
char deviceUUID[37]; // Device UUID
char blockedIPs[][16] = {
  "192.168.1.103",
  "192.168.1.112"
};
char ipAddress[MAX_IP_LEN];

size_t blockedIPCount = sizeof(blockedIPs) / sizeof(blockedIPs[0]);

// Global udp socket and address
int sock;
struct sockaddr_in addr;

// Extract message id from incoming request
void extractMessageID(const char* packetData, char* messageID, size_t messageIDSize) {
  const char* startTag = "MessageID";
  const char* startPtr = strstr(packetData, startTag);
  if (!startPtr) {
    LOG_ERR("MessageID tag not found");
    messageID[0] = '\0'; // Not found
    return;
  }
  startPtr = strchr(startPtr, '>') + 1; // Move past '>'
  while (*startPtr == ' ' || *startPtr == '\n' || *startPtr == '\r') { // Skip whitespace and newlines
    startPtr++;
  }
  const char* endPtr = strstr(startPtr, "</");
  if (!endPtr) {
    LOG_ERR("MessageID end tag not found");
    messageID[0] = '\0'; // Not found
    return;
  }
  size_t len = endPtr - startPtr;

  // Debug log to see what the extracted ID is before checking length
  //log_i("Extracted MessageID: %.*s", (int)len, startPtr);

  if (len >= messageIDSize) {
    LOG_ERR("MessageID is too long: %.*s", (int)len, startPtr);
    messageID[0] = '\0'; // Not found
    return;
  }
  strncpy(messageID, startPtr, len);
  messageID[len] = '\0'; // Null-terminate the extracted ID

  // Remove 'uuid:' prefix if present
  const char prefix[] = "uuid:";
  if (strncmp(messageID, prefix, strlen(prefix)) == 0) {
    memmove(messageID, messageID + strlen(prefix), len - strlen(prefix) + 1);
  }
}



// Generate unique UUID per message
void generateUUID(char* uuid, size_t uuidSize) {
  snprintf(uuid, uuidSize, "%08lx-%04lx-%04lx-%04lx-%012llx",
           static_cast<unsigned long>(esp_random()), esp_random() & 0xFFFF,
           (esp_random() & 0x0FFF) | 0x4000, // UUID version 4
           (esp_random() & 0x3FFF) | 0x8000, // UUID variant 1
           ((unsigned long long)esp_random() << 32) | esp_random());
}

// Function to generate UUID from Chip ID
void generateDeviceUUID(char* uuid, size_t uuidSize) {
  uint32_t chipId = ESP.getEfuseMac(); // Get the chip ID
  snprintf(uuid, uuidSize, "%08lx-%04lx-%04lx-%04lx-%012lx",
           static_cast<unsigned long>((chipId >> 16) & 0xFFFF),
           static_cast<unsigned long>(chipId & 0xFFFF),
           static_cast<unsigned long>((chipId >> 16) & 0xFFFF),
           static_cast<unsigned long>(chipId & 0xFFFF),
           static_cast<unsigned long>(chipId));
}

// Populate Onvif Response from xml templates
void populateOnvifResponse(const char* mainHeader, const char* templateStr, ...) {
  if (onvifBuffer == NULL) {
    LOG_ERR("ONVIF Buffer not allocated! Unable to create response, Starting Onvif");
    startOnvif();
  }

  snprintf((char*)onvifBuffer, ONVIF_BUFFER_SIZE, "%s", mainHeader);

  va_list args;
  va_start(args, templateStr);
  vsnprintf((char*)onvifBuffer + strlen((char*)onvifBuffer), ONVIF_BUFFER_SIZE - strlen((char*)onvifBuffer), templateStr, args);
  va_end(args);

  strncat((char*)onvifBuffer, footer, ONVIF_BUFFER_SIZE - strlen((char*)onvifBuffer) - 1);
}

// Send probe or resolve match
void sendMatch(const char* messageID, const char* relatesToID, const char* action) {
  const char* fullAction;
  if (strcmp(action, "probe") == 0) {
    fullAction = "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches";
  } else if (strcmp(action, "resolve") == 0) {
    fullAction = "http://schemas.xmlsoap.org/ws/2005/04/discovery/ResolveMatches";
  } else {
    LOG_ERR("Wrong action passed!");
    return;
  }
  populateOnvifResponse(discoverNS, onvifMatch, messageID, relatesToID, fullAction,
                        (strcmp(action, "probe") == 0 ? "ProbeMatches" : "ResolveMatches"),
                        (strcmp(action, "probe") == 0 ? "ProbeMatch" : "ResolveMatch"),
                        deviceUUID, APP_NAME, CAM_BOARD, ipAddress,
                        (strcmp(action, "probe") == 0 ? "ProbeMatch" : "ResolveMatch"),
                        (strcmp(action, "probe") == 0 ? "ProbeMatches" : "ResolveMatches"));
}

// Send hello or bye message
void sendMessage(const char* messageType) {
  char messageID[37];
  generateUUID(messageID, sizeof(messageID));
  populateOnvifResponse(discoverNS, messageType, messageID, deviceUUID, APP_NAME, CAM_BOARD, ipAddress);
  sendto(sock, (char*)onvifBuffer, strlen((char*)onvifBuffer), 0, (const struct sockaddr*)&addr, sizeof(addr));
  //log_i("UDP Sent Message: %s", (char*)onvifBuffer);
}

void parseAndApplySettings(const char* requestBody) {
  LOG_INF("Received request body: %s", requestBody);

  // Helper function to extract value from XML
  auto extractValue = [](const char* xml, const char* tag) -> int {
    const char* start = strstr(xml, tag);
    if (start) {
      start = strchr(start, '>') + 1;
      const char* end = strchr(start, '<');
      if (end) {
        char value[16];
        strncpy(value, start, end - start);
        value[end - start] = '\0';
        return atoi(value);
      }
    }
    return -1; // Indicate error
  };
  
  sensor_t* s = esp_camera_sensor_get();
  if (!s) {
    LOG_ERR("Failed to get camera sensor");
    return;
  }
  // Parse XML settings
  int brightness = extractValue(requestBody, "Brightness");
  if (brightness != -1) {
    if (s->set_brightness(s, brightness) == 0) {
      LOG_INF("Brightness set to %d", brightness);
    } else {
      LOG_ERR("Failed to set Brightness to %d", brightness);
    }
  }

  int contrast = extractValue(requestBody, "Contrast");
  if (contrast != -1) {
    if (s->set_contrast(s, contrast) == 0) {
      LOG_INF("Contrast set to %d", contrast);
    } else {
      LOG_ERR("Failed to set Contrast to %d", contrast);
    }
  }

  int saturation = extractValue(requestBody, "ColorSaturation");
  if (saturation != -1) {
    if (s->set_saturation(s, saturation) == 0) {
      LOG_INF("Color Saturation set to %d", saturation);
    } else {
      LOG_ERR("Failed to set Color Saturation to %d", saturation);
    }
  }

  int sharpness = extractValue(requestBody, "Sharpness");
  if (sharpness != -1) {
    if (s->set_sharpness(s, sharpness) == 0) {
      LOG_INF("Sharpness set to %d", sharpness);
    } else {
      LOG_ERR("Failed to set Sharpness to %d", sharpness);
    }
  }

  // Exposure settings
  if (strstr(requestBody, "Exposure")) {
    if (strstr(requestBody, "Mode>AUTO")) {
      if (s->set_exposure_ctrl(s, 1) == 0) {
        LOG_INF("Exposure set to AUTO");
      } else {
        LOG_ERR("Failed to set Exposure to AUTO");
      }
    } else if (strstr(requestBody, "Mode>MANUAL")) {
      if (s->set_exposure_ctrl(s, 0) == 0) {
        LOG_INF("Exposure set to MANUAL");
      } else {
        LOG_ERR("Failed to set Exposure to MANUAL");
      }
    }

    int gain = extractValue(requestBody, "Gain");
    if (gain != -1) {
      if (s->set_agc_gain(s, gain) == 0) {
        LOG_INF("Gain set to %d", gain);
      } else {
        LOG_ERR("Failed to set Gain to %d", gain);
      }
    }

    int exposureTime = extractValue(requestBody, "ExposureTime");
    if (exposureTime != -1) {
      if (s->set_aec_value(s, exposureTime) == 0) {
        LOG_INF("Exposure Time set to %d", exposureTime);
      } else {
        LOG_ERR("Failed to set Exposure Time to %d", exposureTime);
      }
    }
  }

  // White Balance settings  
  if (strstr(requestBody, "WhiteBalance")) {
    if (strstr(requestBody, "Mode>AUTO")) {
      if (s->set_whitebal(s, 1) == 0) {
        LOG_INF("White Balance set to AUTO");
      } else {
        LOG_ERR("Failed to set White Balance to AUTO");
      }
    } else if (strstr(requestBody, "Mode>MANUAL")) {
      if (s->set_whitebal(s, 0) == 0) {
        LOG_INF("White Balance set to MANUAL");
      } else {
        LOG_ERR("Failed to set White Balance to MANUAL");
      }
    }
  }
}

// Http endpoint onvif action responses
void onvifServiceResponse(const char* action, const char* uri, const char* requestBody = nullptr) {
  log_i("Onvif request: %s at URI: %s", action, uri);

  if (strstr(uri, "/device_service")) {
    // Device services
    if (strstr(action, "GetDeviceInformation")) {
      populateOnvifResponse(deviceHeader, getDeviceInfo, onvifManufacturer, onvifModel, APP_VER, "123456", "HW123456");
    } else if (strstr(action, "GetCapabilities")) {
      populateOnvifResponse(maxHeader, getCapabilities, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress);
    } else if (strstr(action, "GetServices")) {
      populateOnvifResponse(deviceHeader, getServices, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress, ipAddress);
    } else if (strstr(action, "GetScopes")) {
      populateOnvifResponse(deviceHeader, getScopes);
    } else if (strstr(action, "GetZeroConfiguration")) {
      populateOnvifResponse(deviceHeader, getZeroConfig, ipAddress);
    } else if (strstr(action, "GetNetworkInterfaces")) {
      populateOnvifResponse(deviceHeader, getNetworkInterfaces, "24:62:AB:D5:4C:18", ipAddress);
    } else if (strstr(action, "GetDNS")) {
      populateOnvifResponse(deviceHeader, getDNS);
    } else if (strstr(action, "GetSystemDateAndTime")) {
      populateOnvifResponse(deviceHeader, getSystemDateAndTime);
    } else {
      snprintf((char*)onvifBuffer, ONVIF_BUFFER_SIZE, "UNKNOWN");
    }
  } else if (strstr(uri, "/media_service") || strstr(uri, "/media2_service")) { // Add media2_service handling
    // Media services
    if (strcmp(action, "GetProfile") == 0) {
      populateOnvifResponse(mediaHeader, getProfiles, "Profile", "Profile", "Profile", "Profile");
    } else if (strcmp(action, "GetProfiles") == 0) {
      if (strstr(uri, "/media2_service")) {
        // Handle Media2 version response
        populateOnvifResponse(mediaHeader, getProfilesMedia2);
      } else {
        // Handle Media1 version response
        populateOnvifResponse(mediaHeader, getProfiles, "Profiles", "Profiles", "Profiles", "Profiles");
      }
    } else if (strstr(action, "GetStreamUri")) {
      populateOnvifResponse(mediaHeader, getStreamUri, ipAddress);
    } else if (strstr(action, "GetSnapshotUri")) {
      populateOnvifResponse(mediaHeader, getSnapshotUri, ipAddress);
    } else if (strstr(action, "GetVideoSources")) {
      populateOnvifResponse(maxHeader, getVideoSources);
    } else if (strstr(action, "GetVideoSourceConfiguration")) {
      populateOnvifResponse(maxHeader, getVideoSourceConfiguration);
    } else if (strstr(action, "GetVideoEncoderConfigurationOptions")) {
      populateOnvifResponse(maxHeader, getVideoEncoderConfigurationOptions);
    } else if (strstr(action, "GetAudioDecoderConfigurations")) {
      populateOnvifResponse(mediaHeader, getAudioDecoderConfigurations);
    } else {
      snprintf((char*)onvifBuffer, ONVIF_BUFFER_SIZE, "UNKNOWN");
    }
  } else if (strstr(uri, "/image_service")) {
    // Imaging services
    if (strstr(action, "GetImagingSettings")) {
      sensor_t* s = esp_camera_sensor_get();
      if (!s) {
        LOG_ERR("Failed to get camera sensor");
        return;
      }

      int brightness = s->status.brightness;
      int contrast = s->status.contrast;
      int colorSaturation = s->status.saturation;
      int sharpness = s->status.sharpness;
      const char* exposureMode = s->status.aec ? "AUTO" : "MANUAL";
      int minExposureTime = s->status.aec2;
      int maxExposureTime = s->status.aec_value;
      int gain = s->status.agc_gain;
      const char* whiteBalanceMode = s->status.awb ? "AUTO" : "MANUAL";

      populateOnvifResponse(maxHeader, getImagingSettings,
                            brightness, contrast, colorSaturation, sharpness,
                            exposureMode, minExposureTime, maxExposureTime, gain,
                            whiteBalanceMode);
    } else if (strstr(action, "GetOptions")) {
      populateOnvifResponse(maxHeader, getImagingOptions);
    } else if (strstr(action, "GetMoveOptions")) {
      populateOnvifResponse(maxHeader, getMoveOptions);
    } else if (strstr(action, "SetImagingSettings")) {
      if (requestBody) parseAndApplySettings(requestBody);
      populateOnvifResponse(maxHeader, setImagingSettings);
    } else {
      snprintf((char*)onvifBuffer, ONVIF_BUFFER_SIZE, "UNKNOWN");
    }
  } else {
    snprintf((char*)onvifBuffer, ONVIF_BUFFER_SIZE, "UNKNOWN");
  }
}

// Function to check if an IP address is blocked
bool isBlocked(const char* ip) {
  for (size_t i = 0; i < blockedIPCount; ++i) {
    if (strcmp(ip, blockedIPs[i]) == 0) {
      return true;
    }
  }
  return false;
}

// Function to process incoming udp packets
void process_packet(const char *packet_data, size_t len, const struct sockaddr_in *sender_addr, int sock) {
  if (onvifBuffer == NULL) {
    LOG_ERR("ONVIF Buffer not allocated!");
    return;
  }
  char messageID[42];
  char relatesToID[42];
  generateUUID(messageID, sizeof(messageID));
  extractMessageID(packet_data, relatesToID, sizeof(relatesToID));
  // Check for Probe
  if (strstr(packet_data, "Probe") != NULL) {
    sendMatch(messageID, relatesToID, "probe");
  }
  // Check for Resolve
  else if (strstr(packet_data, "Resolve") != NULL) {
    sendMatch(messageID, relatesToID, "resolve");
  }
  // Send response
  if (strlen((char*)onvifBuffer) <= 4096) { // have to check max size again was 1444
    sendto(sock, (char*)onvifBuffer, strlen((char*)onvifBuffer), 0, (struct sockaddr *)sender_addr, sizeof(*sender_addr));
  } else {
    LOG_ERR("UDP Failed to send response packet too large");
  }
}

// Hello timer wrapper
void sendHello(void*) {
  sendMessage(onvifHello);
}

//Set udp to non-blocking
bool setNonBlocking(int sock) { 
  int flags = fcntl(sock, F_GETFL, 0); 
  if (flags == -1) { 
    LOG_ERR("Failed to get socket flags"); 
    return false; 
  } 
  if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) { 
    LOG_ERR("Failed to set socket to non-blocking mode"); 
    return false;
  } 
  LOG_INF("Socket set to non-blocking mode");
  return true;
}

// Task to handle UDP server
void onvifTask(void *pvParameters) {
  struct sockaddr_in client_addr;
  char recv_buffer[2048];
  int32_t n;

  while (1) {
    // Handle incoming UDP packets
    socklen_t addr_len = sizeof(client_addr);
    n = recvfrom(sock, recv_buffer, sizeof(recv_buffer) - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
    if (n < 0) {
      if (errno != EWOULDBLOCK) {
        LOG_ERR("UDP Receive failed: errno %d", errno);
      }
    } else {
      char sender_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(client_addr.sin_addr), sender_ip, INET_ADDRSTRLEN);
      if (!isBlocked(sender_ip)) {
        recv_buffer[n] = '\0';
        //LOG_DBG("UDP Received %d bytes from %s:%d", n, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        //LOG_DBG("UDP Data: %s", recv_buffer);
        process_packet(recv_buffer, n, &client_addr, sock);
      }
    }
  }

  stopOnvif(); // Clean up when exiting the task
  vTaskDelete(NULL);
}

// Function to start the ONVIF service
void startOnvif() {
  strncpy(ipAddress, WiFi.localIP().toString().c_str(), MAX_IP_LEN);
  ipAddress[MAX_IP_LEN - 1] = '\0';  // Ensure null-termination
  // Set the device UUID
  generateDeviceUUID(deviceUUID, sizeof(deviceUUID));

  // Allocate buffer for ONVIF UDP and HTTP responses if PSRAM is available
  if (psramFound()) {
    if (onvifBuffer == NULL) {
      onvifBuffer = (uint8_t*)ps_malloc(ONVIF_BUFFER_SIZE);
      if (onvifBuffer == NULL) {
        LOG_ERR("ONVIF Buffer allocation failed!");
      }
    }
  } else {
    LOG_ERR("ONVIF Buffer allocation failed! PSRAM not found");
  }

  // Allocate buffer from regular RAM if PSRAM isn't available ///// TESTING!!!
  if (onvifBuffer == NULL) {
    onvifBuffer = (uint8_t*)malloc(ONVIF_BUFFER_SIZE);
    if (onvifBuffer == NULL) {
      LOG_ERR("ONVIF Buffer allocation failed in regular RAM!");
      return;
    }
  }

  // Create and configure the socket address structure
  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE("UDP", "Socket creation failed: errno %d", errno);
    return;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(ONVIF_PORT);
  addr.sin_addr.s_addr = inet_addr(ONVIF_IP);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_ERR("UDP Socket binding failed: errno %d", errno);
    close(sock);
    return;
  }

  // Set the socket to non-blocking mode
  if (!setNonBlocking(sock)) {
    LOG_ERR("Failed to set socket to non-blocking mode");
    close(sock);
    return;
  }

  // Join multicast group
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(ONVIF_IP);
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
    LOG_ERR("Joining multicast group failed: errno %d", errno);
    close(sock);
    return;
  }

  // Configure esp_timer
  esp_timer_create_args_t timerArgs = {
    .callback = &sendHello,
    .arg = nullptr,
    .name = "helloTimer"
  };
  esp_timer_create(&timerArgs, &helloTimer);
  esp_timer_start_periodic(helloTimer, ONVIF_HELLO_INTERVAL * 1000000); // Convert seconds to microseconds

  // Start the UDP server task
  xTaskCreate(onvifTask, "onvifTask", ONVIF_STACK_SIZE, NULL, ONVIF_PRI, &onvifHandle);
  LOG_INF("ONVIF Started");
  LOG_DBG("Listening on IP: %s, Port: %d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

}

void stopOnvif() {
  // Delete onvif task
  if (onvifHandle != NULL) {
    vTaskDelete(onvifHandle);
    onvifHandle = NULL;
  }
  // Remove the onvif hello timer
  if (helloTimer != NULL) {
    esp_timer_stop(helloTimer);
    esp_timer_delete(helloTimer);
    helloTimer = NULL;
  }
  // Close udp port
  if (sock >= 0) {
    sendMessage(onvifBye); // Send Bye message before closing the socket
    close(sock);
    sock = -1;
  }
  // Free the buffer
  if (onvifBuffer != NULL) {
    free(onvifBuffer);
    onvifBuffer = NULL;
  }
}

#endif