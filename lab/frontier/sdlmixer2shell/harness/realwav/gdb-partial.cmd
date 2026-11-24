# Partial saved-RIP overwrite check (W184). Run from harness/realwav/evidence:
#   gdb -q -batch -x ../gdb-partial.cmd ./realwav-driver-vuln-nossp
# Break at the final FetchXLaw store with length=142; that store targets
# buffer+1128, the low four bytes of WAV_decode's saved RIP in the no-SSP frame.
set pagination off
set confirm off
set print elements 16
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/sdlmixer2shell/deps/SDL_mixer-vuln-src/src/decoder_wav.c:759 if i == 141
run alaw142.wav decode
printf "AT_LAST i=%d length=%d buffer=%p out=%p dest=%p idx=%u\n", i, length, buffer, out, &out[i], buffer[i]
printf "BEFORE_RIP_SLOT "
x/gx (char *)buffer + 1128
printf "LUT_VALUE "
p/x lut[buffer[i]]
next
printf "AFTER_RIP_SLOT "
x/gx (char *)buffer + 1128
printf "AFTER_BYTES_1120_1135\n"
x/16xb (char *)buffer + 1120
printf "FRAME_NOW\n"
bt 4
quit
