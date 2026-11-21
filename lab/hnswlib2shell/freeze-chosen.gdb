set pagination off
set confirm off
set print elements 16
break /tmp/hnsw2-service-out/v09/hnswlib/hnswalg.h:779
run 49733 /tmp/hnsw2-service-out/gdb-received-chosen.bin
set $dst = data_level0_memory_
set $before = *(unsigned long *)($dst + 264)
printf "\n==== CHOSEN-VALUE FREEZE AT PINNED READ ====\n"
printf "dst=%p per=%lu\n", $dst, size_data_per_element_
printf "top chunk header BEFORE copy: "
x/2gx $dst+256
break malloc if *(unsigned long *)($dst + 264) != $before
continue
printf "\n==== TOP CHUNK HEADER AFTER COPY ====\n"
x/2gx $dst+256
printf "expected size field from file bytes at offset 360: 0x1122334455667788\n"
bt 5
quit
