#include "appGlobals.h"
#if INCLUDE_ONVIF
#include "esp_system.h" // Include for esp_random
#include "esp_timer.h"

#define MULTICAST_PORT 3702
#define MULTICAST_IP "239.255.255.250"
// Variables for Hello ONVIF message timing
#define HELLO_INTERVAL 30 // 30 seconds

std::vector<IPAddress> blockedIPs = {IPAddress(192, 168, 1, 103), IPAddress(192, 168, 1, 112)}; // List of IPs to block incoming UDP packets
std::string ipAddress; // Hold the device IP address
std::string deviceUUID; // Device UUID

esp_timer_handle_t hello_timer;
TaskHandle_t udpTaskHandle = NULL;

struct sock_params {
  int32_t sock;
  struct sockaddr_in addr;
};

struct sock_params params; // Global instance

const std::string xmlHeader = 
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
  "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
  "xmlns:tt=\"http://www.onvif.org/ver10/schema\" "
  "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" ";

const std::string xmlFooter = "</s:Body></s:Envelope>";

const std::string xmlDiscoverNS = 
  "xmlns:enc=\"http://www.w3.org/2003/05/soap-encoding\" "
  "xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
  "xmlns:wsa5=\"http://www.w3.org/2005/08/addressing\" "
  "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" "
  "xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">";

std::string sendProbeMatch(const std::string& probeMessageID, const std::string& messageID) {
  return xmlHeader + xmlDiscoverNS +
         "<s:Header>"
         "<wsa:MessageID>uuid:" + messageID + "</wsa:MessageID>"
         "<wsa:RelatesTo>uuid:" + probeMessageID + "</wsa:RelatesTo>"
         "<wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>"
         "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>"
         "</s:Header>"
         "<s:Body>"
         "<d:ProbeMatches>"
         "<d:ProbeMatch>"
         "<wsa:EndpointReference>"
         "<wsa:Address>urn:uuid:" + deviceUUID + "</wsa:Address>"
         "</wsa:EndpointReference>"
         "<d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>"
         "<d:Scopes>"
         "onvif://www.onvif.org/location/country/china "
         "onvif://www.onvif.org/name/" + APP_NAME + " "
         "onvif://www.onvif.org/hardware/" + CAM_BOARD + " "
         "onvif://www.onvif.org/type/audio_encoder "
         "onvif://www.onvif.org/type/video_encoder "
         "onvif://www.onvif.org/type/ptz"
         "</d:Scopes>"
         "<d:XAddrs>http://" + ipAddress + "/onvif/device_service</d:XAddrs>"
         "<d:MetadataVersion>1</d:MetadataVersion>"
         "</d:ProbeMatch>"
         "</d:ProbeMatches>" +
         xmlFooter;
}

std::string sendHello(const std::string& messageID) {
  return xmlHeader + xmlDiscoverNS +
         "<s:Header>"
         "<wsa:MessageID>uuid:" + messageID + "</wsa:MessageID>"
         "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
         "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action>"
         "</s:Header>"
         "<s:Body>"
         "<d:Hello>"
         "<wsa:EndpointReference>"
         "<wsa:Address>urn:uuid:" + deviceUUID + "</wsa:Address>"
         "</wsa:EndpointReference>"
         "<d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>"
         "<d:Scopes>"
         "onvif://www.onvif.org/location/country/australia "
         "onvif://www.onvif.org/name/" + APP_NAME + " "
         "onvif://www.onvif.org/hardware/" + CAM_BOARD + " "
         "onvif://www.onvif.org/type/audio_encoder "
         "onvif://www.onvif.org/type/video_encoder "
         "onvif://www.onvif.org/type/ptz"
         "</d:Scopes>"
         "<d:XAddrs>http://" + ipAddress + "/onvif/device_service</d:XAddrs>"
         "<d:MetadataVersion>1</d:MetadataVersion>"
         "</d:Hello>" +
         xmlFooter;
}

std::string sendBye(const std::string& messageID) {
  return xmlHeader + xmlDiscoverNS +
         "<s:Header>"
         "<wsa:MessageID>uuid:" + messageID + "</wsa:MessageID>"
         "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04/discovery</wsa:To>"
         "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye</wsa:Action>"
         "</s:Header>"
         "<s:Body>"
         "<d:Bye>"
         "<wsa:EndpointReference>"
         "<wsa:Address>urn:uuid:" + deviceUUID + "</wsa:Address>"
         "</wsa:EndpointReference>"
         "</d:Bye>" +
         xmlFooter;
}

std::string extractMessageID(const std::string& packetData) {
  size_t startIndex = packetData.find(":MessageID>");
  if (startIndex == std::string::npos) {
    LOG_ERR("MessageID tag not found");
    return ""; // Not found
  }
  startIndex = packetData.rfind('<', startIndex); // Find the opening '<'
  size_t closeTagStart = packetData.find(">", startIndex); // Find the closing '>'
  if (closeTagStart == std::string::npos) {
    LOG_ERR("MessageID close tag not found");
    return "";
  }
  startIndex = closeTagStart + 1; // Move to the end of the opening tag
  size_t endIndex = packetData.find("</", startIndex); // Find the closing tag
  if (startIndex != std::string::npos && endIndex != std::string::npos) {
    std::string messageID = packetData.substr(startIndex, endIndex - startIndex);
    // Remove 'uuid:' prefix if present
    const std::string prefix = "uuid:";
    if (messageID.find(prefix) == 0) {
      messageID = messageID.substr(prefix.length());
    }
    return messageID;
  } else {
    LOG_ERR("MessageID end tag not found");
  }
  return "";
}

// Generate unique UUID per message
std::string generateUUID() {
  char uuid[37];
  snprintf(uuid, sizeof(uuid), "%08lx-%04x-%04x-%04x-%012llx",
           static_cast<unsigned long>(esp_random()), esp_random() & 0xFFFF,
           (esp_random() & 0x0FFF) | 0x4000, // UUID version 4
           (esp_random() & 0x3FFF) | 0x8000, // UUID variant 1
           ((uint64_t)esp_random() << 32) | esp_random());
  return std::string(uuid);
}

// Function to generate UUID from Chip ID
std::string generateDeviceUUID() {
  uint32_t chipId = ESP.getEfuseMac(); // Get the chip ID
  char uuid[37];
  snprintf(uuid, sizeof(uuid), "%08lx-%04x-%04x-%04x-%012lx",
           static_cast<unsigned long>((chipId >> 16) & 0xFFFF),
           static_cast<unsigned long>(chipId & 0xFFFF),
           static_cast<unsigned long>((chipId >> 16) & 0xFFFF),
           static_cast<unsigned long>(chipId & 0xFFFF),
           static_cast<unsigned long>(chipId));
  return std::string(uuid);
}

// Function to check if an IP address is blocked
bool isBlocked(IPAddress ip) {
  for (auto &blockedIP : blockedIPs) {
    if (ip == blockedIP) {
      return true;
    }
  }
  return false;
}

void sendHelloMessage() {
  std::string helloMessage = sendHello(generateUUID());
  sendto(params.sock, helloMessage.c_str(), helloMessage.length(), 0, (const struct sockaddr*)&(params.addr), sizeof(params.addr));
  LOG_DBG("UDP", "Sent Hello Message: %s", helloMessage.c_str());
}

void sendByeMessage() {
  std::string byeMessage = sendBye(generateUUID());
  sendto(params.sock, byeMessage.c_str(), byeMessage.length(), 0, (const struct sockaddr*)&(params.addr), sizeof(params.addr));
  LOG_DBG("UDP", "Sent Bye Message: %s", byeMessage.c_str());
}

void hello_timer_callback(void* arg) {
  sendHelloMessage();
}


// Function to process incoming packets
void process_packet(const char *packet_data, size_t len, const struct sockaddr_in *sender_addr, int sock) {
  char sender_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(sender_addr->sin_addr), sender_ip, INET_ADDRSTRLEN);
  if (!isBlocked(inet_addr(sender_ip))) {
    std::string packetData(packet_data, len);
    if (packetData.find("Probe") != std::string::npos) {
      std::string probeMessageID = extractMessageID(packetData);
      std::string response = sendProbeMatch(probeMessageID, generateUUID());
      if (response.length() <= 1444) { // 1442
        sendto(sock, response.c_str(), response.length(), 0, (struct sockaddr *)sender_addr, sizeof(*sender_addr));
      } else {
        LOG_ERR("UDP", "Failed to send response packet too large");
      }
    }
  } else {
    LOG_DBG("UDP", "Ignored packet from %s", sender_ip);
  }
}

// Task to handle UDP server
void udp_server_task(void *pvParameters) {
  struct sockaddr_in client_addr;
  char recv_buffer[1024];
  int32_t n;

  // Create and configure the socket address structure
  params.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (params.sock < 0) {
    ESP_LOGE("UDP", "Socket creation failed: errno %d", errno);
    vTaskDelete(NULL);
    return;
  }

  memset(&params.addr, 0, sizeof(params.addr));
  params.addr.sin_family = AF_INET;
  params.addr.sin_port = htons(MULTICAST_PORT);
  params.addr.sin_addr.s_addr = inet_addr(MULTICAST_IP);

  if (bind(params.sock, (struct sockaddr *)&params.addr, sizeof(params.addr)) < 0) {
    LOG_ERR("UDP", "Socket binding failed: errno %d", errno);
    close(params.sock);
    vTaskDelete(NULL);
    return;
  }

  // Configure esp_timer
  esp_timer_create_args_t timer_args = {
    .callback = reinterpret_cast<esp_timer_cb_t>(sendHelloMessage),
    .arg = nullptr,
    .name = "hello_timer"
  };
  esp_timer_create(&timer_args, &hello_timer);
  esp_timer_start_periodic(hello_timer, HELLO_INTERVAL * 1000000); // Convert seconds to microseconds

  while (1) {
    // Handle incoming UDP packets
    socklen_t addr_len = sizeof(client_addr);
    n = recvfrom(params.sock, recv_buffer, sizeof(recv_buffer) - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
    if (n < 0) {
      LOG_ERR("UDP", "Receive failed: errno %d", errno);
    } else {
      recv_buffer[n] = '\0';
      LOG_DBG("UDP", "Received %d bytes from %s:%d", n, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
      LOG_DBG("UDP", "Data: %s", recv_buffer);
      process_packet(recv_buffer, n, &client_addr, params.sock);
    }
  }

  stopOnvif(); // Clean up when exiting the task
  vTaskDelete(NULL);
}


// Function to start the ONVIF service
void startOnvif() {
  // Set the device UUID and IP address once
  deviceUUID = generateDeviceUUID();
  ipAddress = WiFi.localIP().toString().c_str();
  xTaskCreate(udp_server_task, "udp_server_task", 4096, NULL, 5, &udpTaskHandle);
}

void stopOnvif() {
  if (udpTaskHandle != NULL) {
    vTaskDelete(udpTaskHandle);
    udpTaskHandle = NULL;
  }

  if (hello_timer != NULL) {
    esp_timer_stop(hello_timer);
    esp_timer_delete(hello_timer);
    hello_timer = NULL;
  }

  if (params.sock >= 0) {
    sendByeMessage(); // Send Bye message before closing the socket
    close(params.sock);
    params.sock = -1;
  }
}


#endif

