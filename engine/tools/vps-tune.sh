#!/usr/bin/env bash
# vps-tune.sh — low-latency network + clock tuning for the bid VPS (Ubuntu/Debian).
# Run once as root:  sudo bash tools/vps-tune.sh
set -euo pipefail

echo "== 1. Tight NTP (chrony, Indian + AWS time sources)"
apt-get install -y chrony >/dev/null
cat >/etc/chrony/chrony.conf <<'EOF'
server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4
server time.aws.com iburst minpoll 4 maxpoll 6
pool in.pool.ntp.org iburst maxsources 3
makestep 0.1 3
rtcsync
driftfile /var/lib/chrony/chrony.drift
logdir /var/log/chrony
EOF
systemctl restart chrony
sleep 2
chronyc tracking | egrep 'System time|RMS offset|Stratum' || true

echo "== 2. Kernel network: low latency, no slow-start after idle, BBR, fast open"
cat >/etc/sysctl.d/99-bid-lowlat.conf <<'EOF'
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 3
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.busy_poll = 50
net.core.busy_read = 50
EOF
sysctl --system >/dev/null
sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_slow_start_after_idle

echo "== 3. CPU: performance governor (if available), no power saving"
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [ -w "$g" ] && echo performance > "$g" || true; done

echo "== 4. Node process priority (add to your pm2 ecosystem or run manually):"
echo "   sudo nice -n -10 pm2 start bid-engine.js --name bid-engine"
echo "   or: pm2 start bid-engine.js --name bid-engine && sudo renice -n -10 -p \$(pgrep -f bid-engine.js)"

echo "== 5. Verify latency to SAP:"
echo "   node tools/region-probe.js"
echo "Done."
