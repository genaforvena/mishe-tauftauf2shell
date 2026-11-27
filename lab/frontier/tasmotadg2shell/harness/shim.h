// Host shim for the pinned Tasmota SendReceiveDeviceGroupMessage() body.
// Only declarations the extracted function needs are defined here; the sink
// body itself is copied verbatim from the pinned .ino by build.sh.
#pragma once
#include <cstdint>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>

#define PROGMEM
#define PSTR(s) (s)
#define sprintf_P sprintf
#define snprintf_P snprintf
#define USE_RULES 0
#define DEVICE_GROUPS_PORT 4447
#define DEVICE_GROUP_MESSAGE "TASMOTA_DGR"
#define DEVICE_GROUPS_ADDRESS 0
#define TOPSZ 151
#define POWER_ON 1
#define POWER_OFF 0
#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_DEBUG 2
#define DGR_MEMBER_TIMEOUT 45000
#define LOG_LEVEL_DEBUG_MORE 4
#define strncmp_P strncmp
#define FUNC_DEVICE_GROUP_ITEM 42
enum DevGroupMessageType { DGR_MSGTYP_FULL_STATUS, DGR_MSGTYP_PARTIAL_UPDATE,
  DGR_MSGTYP_UPDATE, DGR_MSGTYP_UPDATE_MORE_TO_COME, DGR_MSGTYP_UPDATE_DIRECT,
  DGR_MSGTYPE_UPDATE_COMMAND, DGR_MSGTYPFLAG_WITH_LOCAL = 128 };
enum DevGroupMessageFlag { DGR_FLAG_RESET = 1, DGR_FLAG_STATUS_REQUEST = 2,
  DGR_FLAG_FULL_STATUS = 4, DGR_FLAG_ACK = 8, DGR_FLAG_MORE_TO_COME = 16,
  DGR_FLAG_DIRECT = 32, DGR_FLAG_ANNOUNCEMENT = 64, DGR_FLAG_LOCAL = 128 };
enum DevGroupItem { DGR_ITEM_EOL, DGR_ITEM_STATUS, DGR_ITEM_FLAGS,
  DGR_ITEM_LIGHT_FADE, DGR_ITEM_LIGHT_SPEED, DGR_ITEM_LIGHT_BRI,
  DGR_ITEM_LIGHT_SCHEME, DGR_ITEM_LIGHT_FIXED_COLOR,
  DGR_ITEM_BRI_PRESET_LOW, DGR_ITEM_BRI_PRESET_HIGH, DGR_ITEM_BRI_POWER_ON,
  DGR_ITEM_LAST_8BIT, DGR_ITEM_MAX_8BIT = 63,
  DGR_ITEM_LAST_16BIT, DGR_ITEM_MAX_16BIT = 127,
  DGR_ITEM_POWER, DGR_ITEM_NO_STATUS_SHARE,
  DGR_ITEM_LAST_32BIT, DGR_ITEM_MAX_32BIT = 191,
  DGR_ITEM_EVENT, DGR_ITEM_COMMAND,
  DGR_ITEM_LAST_STRING, DGR_ITEM_MAX_STRING = 223,
  DGR_ITEM_LIGHT_CHANNELS };
enum DevGroupItemFlag { DGR_ITEM_FLAG_NO_SHARE = 1 };
enum DevGroupShareItem { DGR_SHARE_POWER = 1, DGR_SHARE_LIGHT_BRI = 2,
  DGR_SHARE_LIGHT_FADE = 4, DGR_SHARE_LIGHT_SCHEME = 8,
  DGR_SHARE_LIGHT_COLOR = 16, DGR_SHARE_DIMMER_SETTINGS = 32,
  DGR_SHARE_EVENT = 64 };
enum CommandSource { SRC_REMOTE = 22 };

struct IPAddress {
  uint8_t b[4]{};
  uint8_t operator[](int i) const { return b[i]; }
  bool operator==(const IPAddress& o) { return !memcmp(b, o.b, 4); }
  IPAddress() = default;
  IPAddress(int) {}
};

struct device_group_member {
  struct device_group_member * flink;
  IPAddress ip_address;
  uint16_t received_sequence;
  uint16_t acked_sequence;
  uint32_t unicast_count;
};

struct device_group {
  uint32_t next_announcement_time;
  uint32_t next_ack_check_time;
  uint32_t member_timeout_time;
  uint32_t no_status_share;
  uint16_t outgoing_sequence;
  uint16_t last_full_status_sequence;
  uint16_t message_length;
  uint16_t ack_check_interval;
  uint8_t message_header_length;
  uint8_t initial_status_requests_remaining;
  uint8_t multicasts_remaining;
  char group_name[TOPSZ];
  uint8_t message[128];
  struct device_group_member * device_group_members;
};

struct XDRVMAILBOX {
  bool grpflg;
  bool usridx;
  uint16_t command_code;
  uint32_t data_len;
  uint32_t index;
  int32_t payload;
  char *topic;
  char *data;
  char *command;
};
XDRVMAILBOX XdrvMailbox{};
uint8_t device_group_count = 1;
bool first_device_group_is_local = false;
bool ignore_dgr_sends = false;

struct SettingsType {
  struct { bool multiple_device_groups; bool device_groups_enabled; } flag4{};
  uint32_t device_group_share_in;
  uint32_t device_group_share_out;
  uint32_t device_group_tie[8]{};
};
SettingsType SettingsStorage{};
SettingsType * Settings = &SettingsStorage;

struct TasmotaGlobalType {
  bool restart_flag;
  bool skip_light_fade;
  uint32_t devices_present;
  uint32_t power;
};
TasmotaGlobalType TasmotaGlobal{};

#ifdef USE_SHIM_LOOPBACK_UDP
struct WiFiUDPUStub {
  int fd = -1;
  struct sockaddr_in remote{};
  struct sockaddr_in target{};
  uint8_t rx[512]{};
  uint8_t tx[512]{};
  int rxlen = 0;
  int txlen = 0;
  bool beginMulticast(IPAddress, int port) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(port);
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) return false;
    struct timeval tv{0, 200000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return true;
  }
  int parsePacket() {
    socklen_t len = sizeof(remote);
    rxlen = recvfrom(fd, rx, sizeof(rx) - 1, 0, (struct sockaddr *)&remote, &len);
    return rxlen > 0 ? rxlen : 0;
  }
  int read(uint8_t * dst, size_t n) {
    if ((size_t)rxlen < n) n = rxlen;
    memcpy(dst, rx, n);
    return (int)n;
  }
  IPAddress remoteIP() {
    IPAddress ip{};
    uint32_t a = ntohl(remote.sin_addr.s_addr);
    ip.b[0] = (a >> 24) & 0xff; ip.b[1] = (a >> 16) & 0xff;
    ip.b[2] = (a >> 8) & 0xff; ip.b[3] = a & 0xff;
    return ip;
  }
  bool beginPacket(IPAddress ip, uint16_t port) {
    target = {};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    uint32_t a = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3];
    target.sin_addr.s_addr = htonl(a ? a : INADDR_LOOPBACK);
    txlen = 0;
    return fd >= 0;
  }
  size_t write(uint8_t * src, int n) {
    if (txlen + n > (int)sizeof(tx)) return 0;
    memcpy(tx + txlen, src, n);
    txlen += n;
    return n;
  }
  bool endPacket() {
    return sendto(fd, tx, txlen, 0, (struct sockaddr *)&target, sizeof(target)) == txlen;
  }
};
#else
struct WiFiUDPUStub {
  bool beginPacket(IPAddress, uint16_t) { return true; }
  size_t write(uint8_t *, int) { return 0; }
  bool endPacket() { return true; }
  IPAddress remoteIP() { IPAddress ip{}; ip.b[0]=127; ip.b[1]=0; ip.b[2]=0; ip.b[3]=1; return ip; }
};
#endif
WiFiUDPUStub device_groups_udp;
struct device_group * device_groups;

char g_last_log[4096]{};
int g_log_calls = 0;

char * IPAddressToString(const IPAddress& ip_address) {
  static char buffer[16];
  sprintf(buffer, "%u.%u.%u.%u", ip_address[0], ip_address[1], ip_address[2], ip_address[3]);
  return buffer;
}
uint32_t DeviceGroupSharedMask(uint8_t item) {
  uint32_t mask = 0;
  if (item == DGR_ITEM_LIGHT_BRI || item == DGR_ITEM_BRI_POWER_ON) mask = DGR_SHARE_LIGHT_BRI;
  else if (item == DGR_ITEM_POWER) mask = DGR_SHARE_POWER;
  else if (item == DGR_ITEM_LIGHT_SCHEME) mask = DGR_SHARE_LIGHT_SCHEME;
  else if (item == DGR_ITEM_LIGHT_FIXED_COLOR || item == DGR_ITEM_LIGHT_CHANNELS) mask = DGR_SHARE_LIGHT_COLOR;
  else if (item == DGR_ITEM_LIGHT_FADE || item == DGR_ITEM_LIGHT_SPEED) mask = DGR_SHARE_LIGHT_FADE;
  else if (item == DGR_ITEM_BRI_PRESET_LOW || item == DGR_ITEM_BRI_PRESET_HIGH) mask = DGR_SHARE_DIMMER_SETTINGS;
  else if (item == DGR_ITEM_EVENT) mask = DGR_SHARE_EVENT;
  return mask;
}
uint8_t * BeginDeviceGroupMessage(struct device_group * dg, uint16_t, bool = false) {
  return &dg->message[dg->message_header_length];
}
void _SendDeviceGroupMessage(int32_t, DevGroupMessageType, ...) {}
void AddLog(int, const char *, ...) {}
void AddLogData(int, char * data) { g_log_calls++; snprintf(g_last_log, sizeof(g_last_log), "%s", data); }
void XdrvCall(int) {}
void ExecuteCommandPower(uint32_t, uint32_t, CommandSource) {}
void ExecuteCommand(char *, CommandSource) {}
void CmndEvent() {}
uint32_t millis() { return 0; }
void delay(uint32_t) {}
uint32_t random(uint32_t, uint32_t) { return 0; }
