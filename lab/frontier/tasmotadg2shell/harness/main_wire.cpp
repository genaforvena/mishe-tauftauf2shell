// Real loopback UDP path: build a Device Groups packet, send it to 127.0.0.1:4447,
// receive it through the shim's real socket, and run the pinned
// ProcessDeviceGroupMessage() from the pinned source tree.
#include "shim.h"
#include <vector>

void ProcessDeviceGroupMessage(uint8_t *, int);

static void put16(std::vector<uint8_t>& m, uint16_t v) {
  m.push_back(v & 0xff);
  m.push_back((v >> 8) & 0xff);
}

static std::vector<uint8_t> build_message(int numeric, int strings) {
  std::vector<uint8_t> message;
  const char header[] = DEVICE_GROUP_MESSAGE "g";
  for (size_t i = 0; i < sizeof(header); i++) message.push_back((uint8_t)header[i]);
  put16(message, 1);
  put16(message, 0);
  for (int i = 0; i < numeric; i++) {
    message.push_back(DGR_ITEM_LIGHT_BRI);
    message.push_back(0x43);
  }
  for (int s = 0; s < strings; s++) {
    message.push_back(DGR_ITEM_COMMAND);
    message.push_back(8);
    for (int i = 0; i < 8; i++) message.push_back(0x44);
    message.push_back(0);
  }
  message.push_back(DGR_ITEM_EOL);
  return message;
}

int main(int argc, char ** argv) {
  int numeric = argc > 1 ? atoi(argv[1]) : 1;
  int strings = argc > 2 ? atoi(argv[2]) : 0;
  if (numeric < 0 || numeric > 200 || strings < 0 || strings > 8) return 2;

  device_groups = (struct device_group *)calloc(1, sizeof(struct device_group));
  if (!device_groups) return 3;
  strcpy(device_groups->group_name, "g");
  device_groups->message_header_length = 13;
  device_groups->outgoing_sequence = 1;
  device_groups->last_full_status_sequence = 0xffff;
  SettingsStorage.device_group_share_in = 0xffffffff;
  SettingsStorage.device_group_share_out = 0xffffffff;
  if (!device_groups_udp.beginMulticast(IPAddress{}, DEVICE_GROUPS_PORT)) return 5;

  auto message = build_message(numeric, strings);
  int sender = socket(AF_INET, SOCK_DGRAM, 0);
  if (sender < 0) return 6;
  struct sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(DEVICE_GROUPS_PORT);
  inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
  if (sendto(sender, message.data(), message.size(), 0,
             (struct sockaddr *)&dst, sizeof(dst)) != (ssize_t)message.size()) return 7;
  close(sender);
  printf("DGR_WIRE_SENT numeric=%d strings=%d wire_len=%zu\n", numeric, strings, message.size());
  fflush(stdout);

  int length = device_groups_udp.parsePacket();
  if (length <= 0) { printf("DGR_WIRE_NO_PACKET\n"); return 8; }
  uint8_t packet_buffer[512];
  int received = device_groups_udp.read(packet_buffer, sizeof(packet_buffer) - 1);
  if (received > 0) {
    packet_buffer[received] = 0;
    if (!strncmp_P((char *)packet_buffer, DEVICE_GROUP_MESSAGE, sizeof(DEVICE_GROUP_MESSAGE) - 1)) {
      printf("DGR_WIRE_RECEIVED len=%d\n", received);
      fflush(stdout);
      ProcessDeviceGroupMessage(packet_buffer, received);
    }
  }
  printf("DGR_WIRE_DONE log_calls=%d log_len=%zu\n", g_log_calls, strlen(g_last_log));
  return 0;
}
