set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4482
commands
silent
printf "PRE i=%d array=%p rsp=%p rbp=%p dest=%p byte=0x%x\n", i, &type_name, $rsp, $rbp, (char*)&type_name+(4), *(unsigned char*)((char*)&type_name+(4))
printf "PRE-RETS +136=%p +200=%p +312=%p\n", *(void**)((char*)&type_name+136), *(void**)((char*)&type_name+200), *(void**)((char*)&type_name+312)
printf "PRE-FRAME from array+128:\n"
x/48gx (char*)&type_name+128
bt 6
continue
end
break vrpn_Connection.C:4488
commands
silent
printf "POST byte=0x%x RETS +136=%p +200=%p +312=%p\n", *(unsigned char*)((char*)&type_name+(4)), *(void**)((char*)&type_name+136), *(void**)((char*)&type_name+200), *(void**)((char*)&type_name+312)
bt 6
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 14500
