cat <<EOF > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
Group=nogroup
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -confdir /usr/local/etc/xray/config/
RestartSec=5
Restart=always
StandardOutput=file:/var/log/xray/access.log
StandardError=file:/var/log/xray/error.log
SyslogIdentifier=xray
LimitNOFILE=infinity
OOMScoreAdjust=100

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable xray
sudo systemctl start xray
