#!/bin/bash
mkdir -p /etc/xray

ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

coreselect=''
cat> /root/.profile << END
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true
clear
END
chmod 644 /root/.profile

echo -e "[ ${green}INFO${NC} ] Preparing the install file"
apt install git curl -y >/dev/null 2>&1
echo -e "[ ${green}INFO${NC} ] Allright good ... installation file is ready"
sleep 2

mkdir -p /etc/ssnvpn
mkdir -p /etc/ssnvpn/theme
mkdir -p /var/lib/ssnvpn-pro >/dev/null 2>&1
echo "IP=" >> /var/lib/ssnvpn-pro/ipvps.conf

if [ -f "/etc/xray/domain" ]; then
echo ""
echo -e "[ ${green}INFO${NC} ] Script Already Installed"
echo -ne "[ ${yell}WARNING${NC} ] Do you want to install again ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
rm setup.sh
sleep 10
exit 0
else
clear
fi
fi

    # > pasang gotop
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # > Pasang BBR Plus
    wget -qO /tmp/bbr.sh "${REPO}server/bbr.sh" >/dev/null 2>&1
    chmod +x /tmp/bbr.sh && bash /tmp/bbr.sh

echo ""
wget -q https://raw.githubusercontent.com/Paper890/sandi/main/dependencies.sh;chmod +x dependencies.sh;./dependencies.sh
rm dependencies.sh
clear

    echo -e "${red}    ♦️${NC} ${green} CUSTOM SETUP DOMAIN VPS     ${NC}"
    echo -e "${red}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m${NC}"
    echo "1. Use Domain From Script / Gunakan Domain Dari Script"
    echo "2. Choose Your Own Domain / Pilih Domain Sendiri"
    echo -e "${red}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m${NC}"
    read -rp "Choose Your Domain Installation : " dom 

    if test $dom -eq 1; then
    clear
    apt install jq curl -y
    wget -q -O /root/cf "${CDNF}/cf" >/dev/null 2>&1
    chmod +x /root/cf
    bash /root/cf | tee /root/install.log
    print_success "DomainAll"
    elif test $dom -eq 2; then
    read -rp "Enter Your Domain : " domen 
    echo $domen > /root/domain
    echo "$domen" > /root/domain
    echo "$domen" > /root/scdomain
    echo "$domen" > /etc/xray/domain
    echo "$domen" > /etc/xray/scdomain
    echo "IP=$domen" > /var/lib/ssnvpn-pro/ipvps.conf
    cp /root/domain /etc/xray/domain
    else 
    echo "Not Found Argument"
    exit 1
    fi
    echo -e "${GREEN}Done!${NC}"
    sleep 2
    clear
    
#install ssh ovpn
echo -e "$green[INFO]$NC Install SSH"
sleep 2
clear
wget https://raw.githubusercontent.com/Paper890/sandi/main/ssh/ssh-vpn.sh && chmod +x ssh-vpn.sh && ./ssh-vpn.sh
#Instal Xray
echo -e "$green[INFO]$NC Install XRAY!"
sleep 2
clear
wget https://raw.githubusercontent.com/Paper890/sandi/main/xray/ins-xray.sh && chmod +x ins-xray.sh && ./ins-xray.sh
clear
echo -e "$green[INFO]$NC Install SET-BR!"
wget https://raw.githubusercontent.com/Paper890/sandi/main/backup/set-br.sh && chmod +x set-br.sh && ./set-br.sh
clear
echo -e "$green[INFO]$NC Install WEBSOCKET!"
wget https://raw.githubusercontent.com/Paper890/sandi/main/websocket/insshws.sh && chmod +x insshws.sh && ./insshws.sh
clear
wget https://raw.githubusercontent.com/Paper890/sandi/main/websocket/nontls.sh && chmod +x nontls.sh && ./nontls.sh
clear
echo -e "$green[INFO]$NC Download Extra Menu"
sleep 2
wget https://raw.githubusercontent.com/Paper890/sandi/main/update/update.sh && chmod +x update.sh && ./update.sh
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
