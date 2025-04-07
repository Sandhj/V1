#!/bin/bash

GITHUB="https://raw.githubusercontent.com/Paper890/sandi/main/"

mkdir -p /etc/xray

ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1


apt install git curl
apt install jq curl -y


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
rm -f update.sh
clear
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
clear
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

if [ -f "/root/log-install.txt" ]; then
rm /root/log-install.txt > /dev/null 2>&1
fi
if [ -f "/etc/afak.conf" ]; then
rm /etc/afak.conf > /dev/null 2>&1
fi
if [ ! -f "/etc/log-create-user.log" ]; then
echo "Log All Account " > /etc/log-create-user.log
fi
history -c
serverV=$( curl -sS https://raw.githubusercontent.com/Paper890/sandi/main/version  )
echo $serverV > /opt/.ver

curl -sS ifconfig.me > /etc/myipvps

echo " "
echo "=====================-[ AutoScript Detail ]-===================="
echo ""
echo "------------------------------------------------------------"
echo ""
echo ""
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22"  | tee -a log-install.txt
echo "   - SSH Websocket           : 80" | tee -a log-install.txt
echo "   - SSH SSL Websocket       : 443" | tee -a log-install.txt
echo "   - SSH NON-SSL Websocket   : 80, 8880" | tee -a log-install.txt
echo "   - SLOWDNS                 : 5300 [OFF]" | tee -a log-install.txt
echo "   - Stunnel4                : 447, 777" | tee -a log-install.txt
echo "   - Dropbear                : 109, 143" | tee -a log-install.txt
echo "   - Badvpn                  : 7100-7900" | tee -a log-install.txt
echo "   - Nginx                   : 81" | tee -a log-install.txt
echo "   - XRAY  Vmess TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vmess None TLS    : 80" | tee -a log-install.txt
echo "   - XRAY  Vless TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vless None TLS    : 80" | tee -a log-install.txt
echo "   - Trojan GRPC             : 443" | tee -a log-install.txt
echo "   - Trojan WS               : 443" | tee -a log-install.txt
echo "   - Sodosok WS/GRPC         : 443" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo ""
echo ""
echo "------------------------------------------------------------"
echo ""
echo "===============-[ MOD By SAN  ]-==============="
echo -e ""
echo ""
echo "" | tee -a log-install.txt
rm /root/cf.sh >/dev/null 2>&1
rm /root/setup.sh >/dev/null 2>&1
rm /root/insshws.sh 
rm /root/nontls.sh
secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
echo -e "
"
echo -ne "[ ${yell}WARNING${NC} ] Do you want to reboot now ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi
