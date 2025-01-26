// s60sc 2020 - 2024
// RjSachse 2024
#include "appGlobals.h"
#if INCLUDE_ONVIF
#include "onvif.h"
#include "esp_system.h" // Include for esp_random
#include "esp_timer.h"
#include <fcntl.h>

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

// Http endpoint onvif action responses
void onvifServiceResponse(const char* action, const char* uri) {
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
    }
  } else if (strstr(uri, "/media_service")) {
    // Media services
    if (strcmp(action, "GetProfile") == 0) {
      populateOnvifResponse(mediaHeader, getProfiles, "Profile", "Profile", "Profile", "Profile");
    } else if (strcmp(action, "GetProfiles") == 0) {
      populateOnvifResponse(mediaHeader, getProfiles, "Profiles", "Profiles", "Profiles", "Profiles");
    } else if (strstr(action, "GetStreamUri")) {
      populateOnvifResponse(mediaHeader, getStreamUri, ipAddress);
    } else if (strstr(action, "GetSnapshotUri")) {
      populateOnvifResponse(mediaHeader, getSnapshotUri, ipAddress);
    } else if (strstr(action, "GetVideoSources")) {
      populateOnvifResponse(maxHeader, getVideoSources);
    } else if (strstr(action, "GetAudioDecoderConfigurations")) {
      populateOnvifResponse(mediaHeader, getAudioDecoderConfigurations);
    }
  } else if (strstr(uri, "/ptz_service")) {
    // PTZ services
  } else if (strstr(uri, "/imaging_service")) {
    // Imaging services
    //if (strstr(action, "GetImagingSettings")) {
    //  populateOnvifResponse(imagingHeader, getImagingSettings);
    //}
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
void setNonBlocking(int sock) {
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

// Task to handle UDP server
void onvifTask(void *pvParameters) {
  struct sockaddr_in client_addr;
  char recv_buffer[2048];
  int32_t n;

  // Create and configure the socket address structure
  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE("UDP", "Socket creation failed: errno %d", errno);
    vTaskDelete(NULL);
    return;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(ONVIF_PORT);
  addr.sin_addr.s_addr = inet_addr(ONVIF_IP);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_ERR("UDP Socket binding failed: errno %d", errno);
    close(sock);
    vTaskDelete(NULL);
    return;
  }

  // Join multicast group
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = inet_addr(ONVIF_IP);
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
    LOG_ERR("Joining multicast group failed: errno %d", errno);
    close(sock);
    vTaskDelete(NULL);
    return;
  }

  // Set the socket to non-blocking mode
  setNonBlocking(sock);

  // Configure esp_timer
  esp_timer_create_args_t timerArgs = {
    .callback = &sendHello,
    .arg = nullptr,
    .name = "helloTimer"
  };
  esp_timer_create(&timerArgs, &helloTimer);
  esp_timer_start_periodic(helloTimer, ONVIF_HELLO_INTERVAL * 1000000); // Convert seconds to microseconds

  LOG_DBG("Listening on IP: %s, Port: %d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

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
// Station MAC Address
  //esp_read_mac((uint8_t *)staMac, ESP_MAC_WIFI_STA);
  //esp_read_mac((uint8_t *)apMac, ESP_MAC_WIFI_SOFTAP);

  // Start the UDP server task
  xTaskCreate(onvifTask, "onvifTask", ONVIF_STACK_SIZE, NULL, ONVIF_PRI, &onvifHandle);
  LOG_INF("ONVIF Started");
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