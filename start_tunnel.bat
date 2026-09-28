@echo off
cd /d "C:\Users\LENOVO\Downloads\MTTR_Tracker"
"C:\Users\LENOVO\.cloudflared\cloudflared.exe" tunnel --config "C:\Users\LENOVO\Downloads\MTTR_Tracker\mttr-tunnel-config.yml" run > cloudflared_out.log 2> cloudflared_err.log
