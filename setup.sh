#!/bin/bash

# ============= BATAS AWAL SCRIPT UTAMA ============
      mkdir -p /usr/local/etc/xray/config >> /dev/null 2>&1
      mkdir -p /usr/local/etc/xray/dns >> /dev/null 2>&1
      mkdir -p /user /tmp /usr/local/etc/xray /var/log/xray
      touch /usr/local/etc/xray/dns/domain

#Fungsi Input Domain
      echo -e "————————————————————————————————————————————————————————"
      echo -e "                      SETUP DOMAIN"
      echo -e "————————————————————————————————————————————————————————"
      read -r 'Input domain kamu:' dns
      echo "$dns" > /usr/local/etc/xray/dns/domain
      echo "DNS=$dns" > /var/lib/dnsvps.conf
       

# Update package list
      apt update -y
      apt install socat netfilter-persistent bsdmainutils -y
      apt install vnstat lsof fail2ban -y
      apt install jq curl sudo cron -y
      sudo apt update
      sudo apt install -y curl unzip
      apt install build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev openssl libssl-dev gcc clang llvm g++ valgrind make cmake debian-keyring debian-archive-keyring apt-transport-https systemd bind9-host gnupg2 ca-certificates lsb-release ubuntu-keyring debian-archive-keyring -y
      apt install unzip python-is-python3 python3-pip -y
      pip install psutil pandas tabulate rich py-cpuinfo distro requests pycountry geoip2 --break-system-packages

# Istall Xray Core
      LATEST_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name')
      DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/$LATEST_VERSION/Xray-linux-64.zip"

      curl -L -o xray.zip $DOWNLOAD_URL
      sudo unzip -o xray.zip -d /usr/local/bin
      rm xray.zip
      sudo chmod +x /usr/local/bin/xray    

      wget ${GITHUB}service/xray_service.sh && ./xray_service.sh


# Mengumpulkan informasi dari ipinfo.io
      curl -s ipinfo.io/city?token=f209571547ff6b | sudo tee /usr/local/etc/xray/city
      curl -s ipinfo.io/org?token=f209571547ff6b | cut -d " " -f 2-10 | sudo tee /usr/local/etc/xray/org
      curl -s ipinfo.io/timezone?token=f209571547ff6b | sudo tee /usr/local/etc/xray/timezone
      curl -s ipinfo.io/region?token=f209571547ff6b | sudo tee /usr/local/etc/xray/region
      
# Mengunduh dan menginstal Speedtest CLI
      curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash &>/dev/null
      sudo apt-get install -y speedtest &>/dev/null

# Mengatur zona waktu ke Asia/Jakarta
      sudo timedatectl set-timezone Asia/Jakarta &>/dev/null


#Instalasi WireProxy
      rm -rf /usr/local/bin/wireproxy >> /dev/null 2>&1
      wget -O /usr/local/bin/wireproxy ${HOSTING}/wireproxy
      chmod +x /usr/local/bin/wireproxy

      wget ${GITHUB}service/wireproxy_conf.sh && ./wireproxy_conf.sh

# Fungsi untuk mendeteksi OS
detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
  else
    print_error "OS tidak didukung. Hanya mendukung Ubuntu dan Debian."
    exit 1
  fi
}

# Fungsi untuk menambahkan repositori Nginx
add_nginx_repo() {
  if [ "$OS" == "ubuntu" ]; then
    sudo apt install curl gnupg2 ca-certificates lsb-release ubuntu-keyring -y
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/ubuntu `lsb_release -cs` nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
  elif [ "$OS" == "debian" ]; then
    sudo apt install curl gnupg2 ca-certificates lsb-release debian-archive-keyring -y
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/debian `lsb_release -cs` nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
  else
    print_error "OS tidak didukung. Hanya mendukung Ubuntu dan Debian."
    exit 1
  fi
}

# Fungsi untuk menginstal Nginx
install_nginx() {
  sudo apt update
  sudo apt install nginx -y
  sudo systemctl start nginx
  sudo systemctl enable nginx
}

# Fungsi utama
detect_os
add_nginx_repo
install_nginx


# Menghapus konfigurasi default Nginx dan konten default web
print_msg $YB "Menghapus konfigurasi default Nginx dan konten default web..."
rm -rf /etc/nginx/conf.d/default.conf >> /dev/null 2>&1
rm -rf /etc/nginx/sites-enabled/default >> /dev/null 2>&1
rm -rf /etc/nginx/sites-available/default >> /dev/null 2>&1
rm -rf /var/www/html/* >> /dev/null 2>&1
sudo systemctl restart nginx
check_success "Gagal menghapus konfigurasi default Nginx dan konten default web."

# Membuat direktori untuk Xray
print_msg $YB "Membuat direktori untuk Xray di /var/www/html..."
mkdir -p /var/www/html/xray >> /dev/null 2>&1
check_success "Gagal membuat direktori untuk Xray."

# Pesan selesai
print_msg $GB "Pemasangan dan konfigurasi Nginx telah selesai."
sleep 3
clear
systemctl restart nginx
systemctl stop nginx
systemctl stop xray

#Cert Domain
install_acme_sh2() {
    domain=$(cat /usr/local/etc/xray/dns/domain)
    rm -rf ~/.acme.sh/*_ecc >> /dev/null 2>&1
    curl https://get.acme.sh | sh
    source ~/.bashrc
    ~/.acme.sh/acme.sh --register-account -m $(echo $RANDOM | md5sum | head -c 6; echo;)@gmail.com --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d $domain --standalone --listen-v6 --server letsencrypt --keylength ec-256 --fullchain-file /usr/local/etc/xray/fullchain.cer --key-file /usr/local/etc/xray/private.key --reloadcmd "systemctl restart nginx" --force
    chmod 745 /usr/local/etc/xray/private.key
    echo -e "${YB}Sertifikat SSL berhasil dipasang!${NC}"
}

install_acme_sh2

echo -e "${GB}[ INFO ]${NC} ${YB}Setup Nginx & Xray Config${NC}"
# Generate variabel
uuid=$(cat /proc/sys/kernel/random/uuid)
pwtr=$(openssl rand -hex 4)
pwss=$(echo $RANDOM | md5sum | head -c 6; echo;)
userpsk=$(openssl rand -base64 32)
serverpsk=$(openssl rand -base64 32)

# Escape karakter khusus dalam variabel
escaped_uuid=$(printf '%s\n' "$uuid" | sed 's/[\/&]/\\&/g')
escaped_pwtr=$(printf '%s\n' "$pwtr" | sed 's/[\/&]/\\&/g')
escaped_pwss=$(printf '%s\n' "$pwss" | sed 's/[\/&]/\\&/g')
escaped_userpsk=$(printf '%s\n' "$userpsk" | sed 's/[\/&]/\\&/g')
escaped_serverpsk=$(printf '%s\n' "$serverpsk" | sed 's/[\/&]/\\&/g')

# Konfigurasi Xray-core
print_msg $YB "Mengonfigurasi Xray-core..."
wget -q -O /usr/local/etc/xray/config/00_log.json "${HOSTING}/config/00_log.json"
wget -q -O /usr/local/etc/xray/config/01_api.json "${HOSTING}/config/01_api.json"
wget -q -O /usr/local/etc/xray/config/02_dns.json "${HOSTING}/config/02_dns.json"
wget -q -O /usr/local/etc/xray/config/03_policy.json "${HOSTING}/config/03_policy.json"
wget -q -O /usr/local/etc/xray/config/04_inbounds.json "${HOSTING}/config/04_inbounds.json"
wget -q -O /usr/local/etc/xray/config/05_outbonds.json "${HOSTING}/config/05_outbonds.json"
wget -q -O /usr/local/etc/xray/config/06_routing.json "${HOSTING}/config/06_routing.json"
wget -q -O /usr/local/etc/xray/config/07_stats.json "${HOSTING}/config/07_stats.json"

# Ganti placeholder di dalam 04_inbounds JSON 
sed -i \
    -e "s/UUID/$escaped_uuid/g" \
    -e "s/PWTR/$escaped_pwtr/g" \
    -e "s/PWSS/$escaped_pwss/g" \
    -e "s/USERPSK/$escaped_userpsk/g" \
    -e "s/SERVERPSK/$escaped_serverpsk/g" \
    /usr/local/etc/xray/config/04_inbounds.json
sleep 1.5

# Membuat file log Xray yang diperlukan
print_msg $YB "Membuat file log Xray yang diperlukan..."
sudo touch /var/log/xray/access.log /var/log/xray/error.log
sudo chown nobody:nogroup /var/log/xray/access.log /var/log/xray/error.log
sudo chmod 664 /var/log/xray/access.log /var/log/xray/error.log
check_success "Gagal membuat file log Xray yang diperlukan."
sleep 1.5

# Konfigurasi Nginx
print_msg $YB "Mengonfigurasi Nginx..."
wget -q -O /var/www/html/index.html ${HOSTING}/index.html
wget -q -O /etc/nginx/nginx.conf ${HOSTING}/nginx.conf
domain=$(cat /usr/local/etc/xray/dns/domain)
sed -i "s/server_name web.com;/server_name $domain;/g" /etc/nginx/nginx.conf
sed -i "s/server_name \*.web.com;/server_name \*.$domain;/" /etc/nginx/nginx.conf
# Jika sampai di sini tidak ada error, maka konfigurasi berhasil
print_msg $GB "Konfigurasi Xray-core dan Nginx berhasil."
sleep 3
systemctl restart nginx
systemctl restart xray
echo -e "${GB}[ INFO ]${NC} ${YB}Setup Done${NC}"
sleep 3
clear

# Blokir lalu lintas torrent (BitTorrent)
sudo iptables -A INPUT -p udp --dport 6881:6889 -j DROP
sudo iptables -A INPUT -p tcp --dport 6881:6889 -j DROP
# Blokir lalu lintas torrent dengan modul string
sudo iptables -A INPUT -p tcp --dport 6881:6889 -m string --algo bm --string "BitTorrent" -j DROP
sudo iptables -A INPUT -p udp --dport 6881:6889 -m string --algo bm --string "BitTorrent" -j DROP

print_msg $YB "MEMASANG MENU. . ."
cd
mkdir -p /root/san
cd /root/san
wget -q ${HOSTING}/menu/menu
wget -q ${HOSTING}/menu/settingmenu
wget -q ${HOSTING}/menu/sodosokmenu
wget -q ${HOSTING}/menu/trojanmenu
wget -q ${HOSTING}/menu/vlessmenu
wget -q ${HOSTING}/menu/vmessmenu
wget -q ${HOSTING}/menu/update

wget -q ${HOSTING}/other/about
wget -q ${HOSTING}/other/cek-xray
wget -q ${HOSTING}/other/certxray
wget -q ${HOSTING}/other/clear-log
wget -q ${HOSTING}/other/dns
wget -q ${HOSTING}/other/log-xray
wget -q ${HOSTING}/other/route-xray
wget -q ${HOSTING}/other/update-xray
wget -q ${HOSTING}/other/xp2

wget -q ${HOSTING}/xray/ss/create_ss
wget -q ${HOSTING}/xray/ss/delete_ss
wget -q ${HOSTING}/xray/ss/renew_ss
wget -q ${HOSTING}/xray/ss/list_ss

wget -q ${HOSTING}/xray/trojan/create_trojan
wget -q ${HOSTING}/xray/trojan/delete_trojan
wget -q ${HOSTING}/xray/trojan/renew_trojan
wget -q ${HOSTING}/xray/trojan/list_trojan
wget -q ${HOSTING}/xray/trojan/trojan_custom

wget -q ${HOSTING}/xray/vless/create_vless
wget -q ${HOSTING}/xray/vless/delete_vless
wget -q ${HOSTING}/xray/vless/renew_vless
wget -q ${HOSTING}/xray/vless/list_vless
wget -q ${HOSTING}/xray/vless/vless_custom

wget -q ${HOSTING}/xray/vmess/create_vmess
wget -q ${HOSTING}/xray/vmess/delete_vmess
wget -q ${HOSTING}/xray/vmess/renew_vmess
wget -q ${HOSTING}/xray/vmess/list_vmess
wget -q ${HOSTING}/xray/vmess/vmess_custom

wget -q ${HOSTING}/traffic.py

#Berikan Izin Eksekusi dan memindahkan ke /usr/bin
cd
chmod +x /root/san/*
mv /root/san/* /usr/bin/

menu_default() {
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF
}

#Pasang Default Menu Ketika Login VPS
menu_default

#Pasang Web Restore
print_msg $YB "MEMASANG WEB RESTORE. . ."
bash -c "$(wget -qO- https://raw.githubusercontent.com/Sandhj/Web-restore/main/setup.sh)"

cd
echo "0 5 * * * /sbin/reboot" >> /etc/crontab
systemctl restart cron

# Pasang System xp
echo "[Unit]
Description=Auto Remove Expired VMESS Users
After=network.target

[Service]
ExecStart=/usr/bin/bash /usr/bin/xp2
Restart=on-failure

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/xp2.service

echo "[Unit]
Description=Run xp2 script daily at midnight

[Timer]
OnCalendar=*-*-* 00:00:00
Persistent=true

[Install]
WantedBy=timers.target" | sudo tee /etc/systemd/system/xp2.timer

# Reload systemd untuk mengenali service baru
sudo systemctl daemon-reload

# Aktifkan timer agar berjalan otomatis setiap hari pukul 00:00
sudo systemctl enable xp2.timer
sudo systemctl start xp2.timer
