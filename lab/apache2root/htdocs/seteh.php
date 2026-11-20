<?php set_error_handler(function($no,$str){ echo "STALE-HANDLER-FIRED:$str\n"; return true; }); echo "handler set\n";
