/* Harness-only stubs for the standalone MQTT parser reproducer.
 * - lwip_port_rand: required by the unix port arch/cc.h LWIP_RAND hook.
 * - sys_timeout / sys_untimeout: mqtt.c calls them, but this harness never
 *   runs a timer thread (NO_SYS=1, direct mqtt_parse_incoming() call only).
 *   Signatures use void* for the handler because lwip/sys.h hides the timer
 *   typedef under NO_SYS=1; only the link symbols matter here. */
unsigned int lwip_port_rand(void) { return 1u; }

void sys_timeout(unsigned int msecs, void *handler, void *arg)
{
  (void)msecs; (void)handler; (void)arg;
}

void sys_untimeout(void *handler, void *arg)
{
  (void)handler; (void)arg;
}
