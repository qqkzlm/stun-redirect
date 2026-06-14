#!/bin/bash
cd /root
pkill -f stun_redirect_server.py
sleep 1
nohup python3 stun_redirect_server.py > /tmp/stun.log 2>&1 &
sleep 3
echo "Process:"
ps aux | grep stun_redirect_server | grep -v grep
echo "Port:"
netstat -tlnp 2>/dev/null | grep 8800 || ss -tlnp 2>/dev/null | grep 8800
echo "Log:"
tail -5 /tmp/stun.log
