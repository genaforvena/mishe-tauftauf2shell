set pagination off
break fvimportbdf.c:1751 if glyph < 0
run -script import-frompath-save.ff
printf "W30F before glyph=%d fromunicode=%p encname=%p encs=%p\n", glyph, encname->fromunicode, encname, encs
next
next
next
printf "W30F after glyph=%d fromunicode=%p\n", glyph, encname->fromunicode
break iconv if $rdi == 0x414243
commands
silent
printf "W30F iconv-hit cd=%p\n", $rdi
bt 3
continue
end
break EncFromUni
commands
silent
printf "W30F EncFromUni-hit uni=%d\n", uni
continue
end
printf "W30F armed\n"
continue
printf "W30F exited\n"
quit
