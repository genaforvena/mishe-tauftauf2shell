set pagination off
set confirm off
set print elements 16
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/sdlmixer2shell/deps/SDL_mixer-vuln-src/src/decoder_wav.c:759 if i == 255 || i == 1
run alaw256.wav decode
printf "FIRST_OOB i=%d length=%d buffer=%p out=%p\n", i, length, buffer, out
printf "LUT_INDEX=%u LUT_BITS=0x", buffer[i]
p/x lut[buffer[i]]
printf "BASE=%p\n", (char *)(out - (length-1))
x/8xb (char *)(out - (length-1)) + 2040
x/8xb (char *)(out - (length-1)) + 1020
x/gx (char *)(out - (length-1)) + 1128
frame 2
info frame
p &buffer
continue
printf "AT_I1 i=%d length=%d buffer=%p out=%p\n", i, length, buffer, out
printf "LUT_INDEX=%u LUT_BITS=0x", buffer[i]
p/x lut[buffer[i]]
printf "BASE=%p\n", (char *)(out - (length-1))
x/8xb (char *)(out - (length-1)) + 1020
x/4xb (char *)(out - (length-1)) + 1128
bt 4
frame 2
info frame
info locals
quit
