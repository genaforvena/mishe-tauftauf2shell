set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script open-path.ff
bt 10
quit
