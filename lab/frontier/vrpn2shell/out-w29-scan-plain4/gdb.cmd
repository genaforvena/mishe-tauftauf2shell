set pagination off
set confirm off
source lab/frontier/vrpn2shell/w29-scan.py
break vrpn_Connection.C:405
commands
silent
python w29_scan()
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15364
