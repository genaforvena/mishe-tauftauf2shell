#ifndef STUB_GPHOTO2_H
#define STUB_GPHOTO2_H
/* Harness stubs: only the types and constants the pinned source touches. */
typedef struct _Camera Camera;
typedef struct _GPPort GPPort;
typedef struct _CameraPrivateLibrary CameraPrivateLibrary;

#define GP_OK 0
#define GP_ERROR (-1)
#define GP_ERROR_NOT_SUPPORTED (-2)
/* Real libgphoto2 uses a different numeric value; this stub value is not
   compared against upstream, only against the fixed build's return. */
#define GP_ERROR_CORRUPTED_DATA (-3)

struct _Camera {
    GPPort *port;
    CameraPrivateLibrary *pl;
};
#endif
