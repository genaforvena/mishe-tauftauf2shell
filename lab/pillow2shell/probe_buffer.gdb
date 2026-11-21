# Print the tile buffer address and dump the host type image for the W7
# layout calibration performed by calibrate_file_case.py.
set breakpoint pending on
break ImagingJpegDecode
run
set $b=(unsigned char*)state->buffer
printf "BUFADDR=%lx\n",$b
dump binary memory /tmp/pw2-w7cal/realtype.bin (char*)&PyUnicode_Type (char*)&PyUnicode_Type+416
quit
