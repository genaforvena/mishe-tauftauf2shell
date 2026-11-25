set pagination off
set confirm off
set breakpoint pending on
source lab/frontier/ccextractor2shell/real-build/gdb-w8-postfree.py
break ccx_gxf.c:1220
run
set $buf = (unsigned long)data->buffer
python heap_state("parse")
break free if $rdi == $buf
continue
python heap_state("free-entry")
finish
python heap_state("free-return")
python start_after()
break exit
continue
python heap_state("exit")
quit
