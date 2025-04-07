#!/bin/bash

GITHUB="https://raw.githubusercontent.com/Paper890/sandi/main/"

mkdir -p /etc/xray

ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1


apt install git curl
apt install jq curl -y

# INSTAL PAKET SYSTEM YANG DU BUTUHKAN
wget ${GITHUB}dependencies.sh && chmod +x dependencies.sh && ./dependencies.sh

# SETUP DOMAIN
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "        SETUP YOUR DOMAIN FOR THIS SCRIPT"
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
read -rp "Enter Your Domain : " domen 

# SAVE INFORMASI DOMAIN  
echo $domen > /root/domain
echo "$domen" > /root/domain
echo "$domen" > /root/scdomain
echo "$domen" > /etc/xray/domain
echo "$domen" > /etc/xray/scdomain
echo "IP=$domen" > /var/lib/ssnvpn-pro/ipvps.conf
  
# INSTALL VPN
wget ${GITHUB}ssh/ssh-vpn.sh && chmod +x ssh-vpn.sh && ./ssh-vpn.sh
wget ${GITHUB}xray/ins-xray.sh && chmod +x ins-xray.sh && ./ins-xray.sh
wget ${GITHUB}websocket/insshws.sh && chmod +x insshws.sh && ./insshws.sh
wget ${GITHUB}websocket/nontls.sh && chmod +x nontls.sh && ./nontls.sh

# PASANG MENU
wget ${GITHUB}update/update.sh && chmod +x update.sh && ./update.sh

# PASANG MENU DEFAULT
cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
menu
END
chmod 644 /root/.profile

service_detail="
═════════⊱≼ AUTOSCRIPT SERVICE ≽⊰═════════

OpenSSH                 : 22
SSH Websocket           : 80
SSH SSL Websocket       : 443
SSH NON-SSL Websocket   : 80
Badvpn                  : 7100-7900
XRAY  Vmess             : 443/80
XRAY  Vless             : 443/80
XRAY  Trojan            : 443

Mod Script By : ✴️sansan✴️
══════════════════════════════════════
Succesfully Setup This Script Please Reboot Your VPS
"
echo -e "$service_detail"
