# W207: snapshot the real SDL_mixer heap immediately before and after the
# 30 file-chosen OOB stores. Stop 1 = start of expansion loop (line 4043),
# stop 2 = source div-overflow guard (line 4054). No consumer source is
# modified; the binary is the unmodified vendored stb_vorbis v1.22 build.
set pagination off
set confirm off
break stb_vorbis.h:4043
break stb_vorbis.h:4054
run evidence/chosen.ogg
printf "W207_PRE mult=%p i=%d j=%d k=%d div=%u lv=%d\n", c->multiplicands, i, j, k, div, c->lookup_values
x/48gx c->multiplicands-32
printf "W207_PRE_CHUNK hdr=%lx size=%ld\n", *(unsigned long*)((char*)c->multiplicands-8), (*(unsigned long*)((char*)c->multiplicands-8) & -2)
continue
printf "W207_POST mult=%p i=%d j=%d k=%d div=%u lv=%d\n", c->multiplicands, i, j, k, div, c->lookup_values
x/48gx c->multiplicands-32
printf "W207_POST_FLOATS\n"
x/32wx c->multiplicands
printf "W207_BACKTRACE\n"
bt 8
quit
