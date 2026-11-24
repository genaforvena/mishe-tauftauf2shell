// Lab-only harness: open one local file through the real MediaInfoLib API.
#include "MediaInfo/MediaInfo.h"

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    MediaInfoLib::MediaInfo MI;
    MI.Open(argv[1]);
    return 0;
}
