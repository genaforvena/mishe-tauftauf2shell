#ifndef STUB_GPHOTO2_PORT_H
#define STUB_GPHOTO2_PORT_H
typedef struct _GPPort GPPort;
struct _GPPort { int stub; };

typedef struct { int inep; } GPPortSettingsUsb;
typedef struct {
    GPPortSettingsUsb usb;
} GPPortSettings;
int gp_port_get_settings(GPPort *port, GPPortSettings *settings);
int gp_port_set_settings(GPPort *port, GPPortSettings settings);
int gp_port_close(GPPort *port);
int gp_port_open(GPPort *port);
#endif
