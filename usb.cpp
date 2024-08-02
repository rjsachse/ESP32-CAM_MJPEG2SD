#include "appGlobals.h"

#if INCLUDE_USB 

#if !SOC_USB_OTG_SUPPORTED || ARDUINO_USB_MODE
#error Device does not support USB_OTG or native USB CDC/JTAG is selected
#endif

#include <USB.h>
#include <USBMSC.h>
#include "FirmwareMSC.h"

// USB Mass Storage Class (MSC) object
USBMSC msc;

#if !ARDUINO_USB_CDC_ON_BOOT
USBCDC USBSerial;
#endif

#if !ARDUINO_USB_MSC_ON_BOOT
FirmwareMSC MSC_Update;
#endif

static int32_t onWrite(uint32_t lba, uint32_t offset, uint8_t *buffer, uint32_t bufsize) {
  uint32_t secSize = SD_MMC.sectorSize();
  if (!secSize) {
    return false;  // disk error
  }
  log_v("Write lba: %ld\toffset: %ld\tbufsize: %ld", lba, offset, bufsize);
  for (int x = 0; x < bufsize / secSize; x++) {
    uint8_t blkbuffer[secSize];
    memcpy(blkbuffer, (uint8_t *)buffer + secSize * x, secSize);
    if (!SD_MMC.writeRAW(blkbuffer, lba + x)) {
      return false;
    }
  }
  return bufsize;
}

static int32_t onRead(uint32_t lba, uint32_t offset, void *buffer, uint32_t bufsize) {
  uint32_t secSize = SD_MMC.sectorSize();
  if (!secSize) {
    return false;  // disk error
  }
  log_v("Read lba: %ld\toffset: %ld\tbufsize: %ld\tsector: %lu", lba, offset, bufsize, secSize);
  for (int x = 0; x < bufsize / secSize; x++) {
    if (!SD_MMC.readRAW((uint8_t *)buffer + (x * secSize), lba + x)) {
      return false;  // outside of volume boundary
    }
  }
  return bufsize;
}

static bool onStartStop(uint8_t power_condition, bool start, bool load_eject) {
  log_i("Start/Stop power: %u\tstart: %d\teject: %d", power_condition, start, load_eject);
  return true;
}

static void usbEventCallback(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  if (event_base == ARDUINO_USB_EVENTS) {
    arduino_usb_event_data_t *data = (arduino_usb_event_data_t *)event_data;
    switch (event_id) {
      case ARDUINO_USB_STARTED_EVENT: LOG_INF("USB PLUGGED"); break;
      case ARDUINO_USB_STOPPED_EVENT: LOG_INF("USB UNPLUGGED"); break;
      case ARDUINO_USB_SUSPEND_EVENT: LOG_INF("USB SUSPENDED: remote_wakeup_en: %u\n", data->suspend.remote_wakeup_en); break;
      case ARDUINO_USB_RESUME_EVENT:  LOG_INF("USB RESUMED"); break;

      default: break;
    }
  } else if (event_base == ARDUINO_USB_CDC_EVENTS) {
    arduino_usb_cdc_event_data_t *data = (arduino_usb_cdc_event_data_t *)event_data;
    switch (event_id) {
      case ARDUINO_USB_CDC_CONNECTED_EVENT:    LOG_INF("CDC CONNECTED"); break;
      case ARDUINO_USB_CDC_DISCONNECTED_EVENT: LOG_INF("CDC DISCONNECTED"); break;
      case ARDUINO_USB_CDC_LINE_STATE_EVENT:   LOG_INF("CDC LINE STATE: dtr: %u, rts: %u\n", data->line_state.dtr, data->line_state.rts); break;
      case ARDUINO_USB_CDC_LINE_CODING_EVENT:
        LOG_INF(
          "CDC LINE CODING: bit_rate: %lu, data_bits: %u, stop_bits: %u, parity: %u\n", data->line_coding.bit_rate, data->line_coding.data_bits,
          data->line_coding.stop_bits, data->line_coding.parity
        );
        break;
      case ARDUINO_USB_CDC_RX_EVENT:
        LOG_INF("CDC RX [%u]:", data->rx.len);
        {
          uint8_t buf[data->rx.len];
          size_t len = USBSerial.read(buf, data->rx.len);
          Serial.write(buf, len);
        }
        Serial.println();
        break;
      case ARDUINO_USB_CDC_RX_OVERFLOW_EVENT: LOG_INF("CDC RX Overflow of %d bytes", data->rx_overflow.dropped_bytes); break;

      default: break;
    }
  } else if (event_base == ARDUINO_FIRMWARE_MSC_EVENTS) {
    arduino_firmware_msc_event_data_t *data = (arduino_firmware_msc_event_data_t *)event_data;
    switch (event_id) {
      case ARDUINO_FIRMWARE_MSC_START_EVENT: LOG_INF("MSC Update Start"); break;
      case ARDUINO_FIRMWARE_MSC_WRITE_EVENT:
        //Serial.printf("MSC Update Write %u bytes at offset %u\n", data->write.size, data->write.offset);
        Serial.print(".");
        break;
      case ARDUINO_FIRMWARE_MSC_END_EVENT:  LOG_INF("\nMSC Update End: %u bytes\n", data->end.size); break;
      case ARDUINO_FIRMWARE_MSC_ERROR_EVENT: LOG_INF("MSC Update ERROR! Progress: %u bytes\n", data->error.size); break;
      case ARDUINO_FIRMWARE_MSC_POWER_EVENT:
        Serial.printf("MSC Update Power: power: %u, start: %u, eject: %u", data->power.power_condition, data->power.start, data->power.load_eject);
        break;

      default: break;
    }
  }
}

void startUsbMsc() {

  LOG_INF("Initializing MSC");
  // Initialize USB metadata and callbacks for MSC (Mass Storage Class)
  msc.vendorID("ESP32");
  msc.productID("USB_MSC");
  msc.productRevision("1.0");
  msc.onRead(onRead);
  msc.onWrite(onWrite);
  msc.onStartStop(onStartStop);
  msc.mediaPresent(true);
  msc.begin(SD_MMC.numSectors(), SD_MMC.sectorSize());

  LOG_INF("Initializing USB");

  USB.onEvent(usbEventCallback);
  USBSerial.onEvent(usbEventCallback);
  USB.webUSB(true);
  // Set the URL for your WebUSB landing page
  USB.webUSBURL("https://docs.espressif.com/projects/arduino-esp32/en/latest/_static/webusb.html");

  USBSerial.begin();
  MSC_Update.onEvent(usbEventCallback);
  MSC_Update.begin();
  USB.begin();

  LOG_INF("Card Size: %lluMB\n", SD_MMC.totalBytes() / 1024 / 1024);
  LOG_INF("Sector: %d\tCount: %d\n", SD_MMC.sectorSize(), SD_MMC.numSectors());
}

void stopUsbMsc (){
  msc.end();
}
#endif
