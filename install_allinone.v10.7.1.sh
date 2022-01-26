#!/usr/bin/env bash

# Author: alexseg -

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

export DEBIAN_FRONTEND=noninteractive

# ###############################################################

# Variables globales
_etc_default_is_dhcp_server=0
_etc_dhcp_dhcpd_conf=0
_etc_dhcp_dhclient_conf=0
_etc_resolv_conf=0
_etc_default_bind9=0
_etc_default_bind9=0
_etc_bind_named_conf_local=0
_etc_bind_db_conexionlinux_com=0
_etc_bind_db_conexionlinux_com_fwd=0
_etc_bind_db_conexionlinux_com_rev=0
_etc_squid_squid_conf=0
_etc_squid_squid_access_csv=0
_etc_squid_url_deny_AllPorns_txt=0
_etc_squid_url_deny_AllProfiles_txt=0
_etc_squid_squid_access_sh=0
_etc_mime_types=0
_etc_apache2_sites_enabled_000_default_conf=0
_etc_apache2_sites_available_000_default_conf=0
_var_www_conexionlinux_com_public_html_index_html=0
_var_www_wpad_conexionlinux_com_public_html_wpad_dat=0
_var_www_intranet_conexionlinux_com_public_html_index_html=0
_etc_apache2_sites_available_conexionlinux_com_conf=0
_etc_apache2_sites_available_wpad_conexionlinux_com_conf=0
_etc_apache2_sites_available_intranet_conexionlinux_com_conf=0
_etc_apache2_ports_conf=0
_etc_rsyslog_conf=0
_root_AllInOne_v7_1_cfg=0
_root_AllInOne_v7_1_sh=0
_usr_lib_systemd_system_allinone_service=0

# ###############################################################
# RELOAD VARIABLE FRON CFG FILE

if [ -f $(pwd)/data.cfg ];then
        . $(pwd)/data.cfg
fi
# ###############################################################

trap ctrl_c INT

function ctrl_c() {
  echo -e "\n${yellowColour}[*]${endColour}${grayColour}Saliendo${endColour}"
  tput cnorm
  exit 0
}

# Generando repositorio local
# Una vez instalado todo el sistema AllInone + media server
# 1) borramos lock partial/ 2) Generamos file Packages 3) Comprimimos todo el contenido .deb + Packages files
# apt-get install dpkg-dev -y
# cd /var/cache/apt/archives
# rm /var/cache/apt/archives/{lock,partial/} -rf
# dpkg-scanpackages . /dev/null > Packages
# tar -cf repository_debs.tar *

#Creamos repositorios locales
# mkdir /opt/debs
# tar -xf repository_debs.tar -C  /opt/debs
# sed -i "s/^deb/#deb/g" /etc/apt/sources.list
# echo "deb [trusted=yes] file:///opt/debs ./" >> /etc/apt/sources.list
# apt-get update

function helpPanel(){
	echo -e "\n${yellowColour}[*]${endColour}${grayColour} Uso: $0${endColour}"
	echo -e "\n\t${purpleColour}d)${endColour}${yellowColour} (fqdn) ${endColour}"
	echo -e "\t\t${redColour}example: -d munixxx-master.munixxx.gob.pe${endColour}"
	echo -e "\t${purpleColour}n)${endColour}${yellowColour} Segmento red local${endColour}"
	echo -e "\t\t${redColour}example: -n 192.168.0.0/24${endColour}"
	echo -e "\t${purpleColour}h)${endColour}${yellowColour} Mostrar este panel de ayuda${endColour}"
	echo -e "\t\t${redColour}example: -h ${endColour}"

	exit 0
}

function dependencies_hardware(){
  tput civis
  clear
  declare -i dependencies_hardware_counter=0
  echo -e "${redColour}[*]${endColour}${blueColour} Dependencias de Hardware${endColour}\n"

  echo -n -e "\t${yellowColour}[-]${endColour}${grayColour}Prueba de Interfaces minimas de red (2 nic)....${endColour}"
  interfaces=$(ip a s | grep -oP ':\sen[ops].*:\s' | tr -d ': ')
  interfaces=($interfaces)        # convert variable to array
  if [ ${#interfaces[@]} -ge 2 ]; then
    echo -e "\t\tEncontados NICs=${#interfaces[@]} \t\t==> (V) - Pass"
    dependencies_hardware_counter+=1
  else
    echo ${#interfaces[@]}
    echo -e "\t\tEncontados NICs=${#interfaces[@]} ==> (X) Fail"
  fi

  echo -n -e "\t${yellowColour}[-]${endColour}${grayColour}Prueba de Memoria minima 3000 mb...............${endColour}"
  total_memory=$(( $(cat /proc/meminfo | grep MemTotal | awk {'print $2'})/1024 ))    # kB
  if [ $total_memory -gt 3000 ]; then
      echo -e "\t\tEncontados Memoria=${total_memory} mb \t==> (V) - Pass"
      dependencies_hardware_counter+=1
  else
      echo -e "\t\t\tEncontados Memoria=${total_memory} mb ==> (X) - Fail"
  fi



  echo -n -e "\t${yellowColour}[-]${endColour}${grayColour}Prueba de Cantidad de discos duro (2 discos)...${endColour}"
  total_disks=$(fdisk -l | grep -oP 'Disk\s*\/dev/sd[abc]'   | cut -d ' ' -f 2 | cut -d '/' -f 3 | xargs)
  total_disks=($total_disks)
  if [ ${#total_disks[@]} -ge 2 ]; then
      echo -e "\t\tEncontados discos=${#total_disks[@]} \t\t==> (V) - Pass"
      dependencies_hardware_counter+=1
  else
      echo -e "\tEncontados discos=${#total_disks[@]} ==> (X) - Fail"
  fi

  if [ $dependencies_hardware_counter -eq 3 ];then
      echo -e "\n\t\t${redColour}Dependencias Hardware :${endColour}${yellowColour} (V) - Exitoso${endColour}"
  else
      echo -e "\nDependencias Hardware : (X) - Fallo"
      exit 1
  fi

  sleep 3s
}

function adaptando_kernel_eth(){

    echo -e "\n\n${redColour}[*]${endColour}${blueColour} Adaptando kernel interfaces red ethX${endColour}\n"

    sed -i 's/^GRUB_CMDLINE_LINUX=""$/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/' /etc/default/grub
    grub-mkconfig -o /boot/grub/grub.cfg

    [ "$?" != "0" ] && exit 1 || echo -e """

        \n# The primary network interface
        \tallow-hotplug eth0
        \tiface eth0 inet dhcp

        \n# The second network interface
        \tallow-hotplug eth1
        \tiface eth1 inet static
        \taddress 192.168.0.1
        \tnetmask 255.255.252.0
        \tnetwork 192.168.0.0
        \nbroadcast 192.168.3.255
        """ >> /etc/network/interfaces

    echo -e "\n\t\t${redColour}Adaptando kernel :${endColour}${yellowColour} (V) - Exitoso${endColour}\n\n"
    sleep 3s
}

function local_repository() {
    clear
    echo -e "${redColour}[*]${endColour}${blueColour} Local repository${endColour}\n"
    mkdir -p /opt/debs
    if [ -f /root/repository_debs.tar ]; then
        tar -xf /root/repository_debs.tar -C  /opt/debs
        sed -i "s/^deb/#deb/g" /etc/apt/sources.list
        echo "deb [trusted=yes] file:///opt/debs ./" >> /etc/apt/sources.list
        apt-get update -y 1>/dev/null
    else
        echo "donde esta el repositorio debs comprimido? pe"
        exit 1
    fi

    sleep 3
}

function dependencies_software(){

      echo -e "\n\n${redColour}[*]${endColour}${blueColour} Instalando Dependencias Software${endColour}\n"

      apt-get update -y

      [ "$?" != "0" ] && exit 1 || apt-get install libass9 -y
      [ "$?" != "0" ] && exit 1 || apt-get install libdrm-intel1 -y
      [ "$?" != "0" ] && exit 1 || apt-get install libdrm2 -y
      [ "$?" != "0" ] && exit 1 || apt-get install gnupg -y
      [ "$?" != "0" ] && exit 1 || apt-get install git -y
      [ "$?" != "0" ] && exit 1 || apt-get install apt-transport-https -y
      [ "$?" != "0" ] && exit 1 || apt-get install ca-certificates -y
      [ "$?" != "0" ] && exit 1 || apt-get install curl -y
      [ "$?" != "0" ] && exit 1 || apt-get install tmux -y
      [ "$?" != "0" ] && exit 1 || apt-get install vim -y
      [ "$?" != "0" ] && exit 1 || apt-get install iptables -y
      [ "$?" != "0" ] && exit 1 || apt-get install dos2unix -y
      [ "$?" != "0" ] && exit 1 || apt-get install openvpn -y
      [ "$?" != "0" ] && exit 1 || apt-get install tcpdump -y
      [ "$?" != "0" ] && exit 1 || apt-get install tshark -y
      [ "$?" != "0" ] && exit 1 || apt-get install curl  -y
      [ "$?" != "0" ] && exit 1 || apt-get install wget  -y
      [ "$?" != "0" ] && exit 1 || apt-get install tree  -y
      [ "$?" != "0" ] && exit 1 || apt-get install pciutils -y
      [ "$?" != "0" ] && exit 1 || apt-get install bwm-ng  -y
      [ "$?" != "0" ] && exit 1 || apt-get install iftop -y
      [ "$?" != "0" ] && exit 1 || apt-get install iptraf -y
      [ "$?" != "0" ] && exit 1 || apt-get install tcptrack -y

      [ "$?" != "0" ] && exit 1 || apt-get install sudo -y
      [ "$?" != "0" ] && exit 1 || adduser soporte sudo
      [ "$?" != "0" ] && exit 1 || chmod 0440 /etc/sudoers



      echo -e "\n\t\t${redColour}Instalacion dependencias software :${endColour}${yellowColour} (V) - Exitoso${endColour}"
      sleep 3s
}

function install_services(){

      echo -e "\n\n${redColour}[*]${endColour}${blueColour} Instalando Dependencias Services${endColour}\n"

    # Stop/Disable NetworkManage
      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} Stop/Disable NetworkManager${endColour}\n"
      systemctl stop NetworkManager 2> /dev/null
      systemctl disable NetworkManager 2> /dev/null

    # ssh server
      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} Install ssh server, port change and Permit root${endColour}\n"
      [ "$?" != "0" ] && exit 1 || apt-get install openssh-server -y 1>/dev/null
      [ "$?" != "0" ] && exit 1 || sed -i 's/^#Port .*/Port 25622/' /etc/ssh/sshd_config
      [ "$?" != "0" ] && exit 1 || sed -i 's/^#PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
      [ "$?" != "0" ] && exit 1 || sed -i 's/^#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config
      [ "$?" != "0" ] && exit 1 ||  systemctl restart ssh  2> /dev/null
      [ "$?" != "0" ] && exit 1 || systemctl enable ssh  >/dev/null 2>&1

      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} Generando llaves publicas publica y privada${endColour}\n"
      [ "$?" != "0" ] && exit 1 || ssh-keygen -t rsa -q -f "$HOME/.ssh/id_rsa" -N ""



    # dhcp service - isc-dhcp-server
      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} Installing dhcp server${endColour}\n"
      [ "$?" != "0" ] && exit 1 || apt-get install isc-dhcp-server -y 1>/dev/null

          # /etc/default/isc-dhcp-server
          [ "$?" != "0" ] && exit 1 || echo $_etc_default_is_dhcp_server| base64 -d > /etc/default/isc-dhcp-server
          [ "$?" != "0" ] && exit 1 || chown root:root /etc/default/isc-dhcp-server
          [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/default/isc-dhcp-server

          # /etc/dhcp/dhcpd.conf
          [ "$?" != "0" ] && exit 1 || echo $_etc_dhcp_dhcpd_conf | base64 -d > /etc/dhcp/dhcpd.conf
          [ "$?" != "0" ] && exit 1 || sed -i "s/conexionlinux.com/$getDomain/g" /etc/dhcp/dhcpd.conf
          [ "$?" != "0" ] && exit 1 || chown root:root /etc/dhcp/dhcpd.conf
          [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/dhcp/dhcpd.conf

          systemctl stop isc-dhcp-server.service 2> /dev/null
          systemctl start isc-dhcp-server.service 2> /dev/null
          systemctl enable isc-dhcp-server.service >/dev/null 2>&1

      # bind9 service
      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} Installing bind server${endColour}\n"
      [ "$?" != "0" ] && exit 1 || apt-get install bind9 bind9-doc dnsutils -y 1>/dev/null

          #/etc/default/bind9
          [ "$?" != "0" ] && exit 1 || echo $_etc_default_bind9 | base64 -d > /etc/default/bind9
          [ "$?" != "0" ] && exit 1 || chown root:bind /etc/default/bind9
          [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/default/bind9

          # /etc/bind/named.conf.options
          [ "$?" != "0" ] && exit 1 || echo $_etc_bind_named_conf_options | base64 -d > /etc/bind/named.conf.options
          [ "$?" != "0" ] && exit 1 || chown root:bind /etc/bind/named.conf.options
          [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/bind/named.conf.options
          [ "$?" != "0" ] && exit 1 || sed -i "s/conexionlinux.com/${getDomain}/g" /etc/bind/named.conf.options
          named-checkconf 1>/dev/null

          # /etc/bind/named.conf.local
          [ "$?" != "0" ] && exit 1 || echo $_etc_bind_named_conf_local | base64 -d > /etc/bind/named.conf.local
          [ "$?" != "0" ] && exit 1 || chown root:bind /etc/bind/named.conf.local
          [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/bind/named.conf.local
          [ "$?" != "0" ] && exit 1 || sed -i "s/conexionlinux.com/${getDomain}/g" /etc/bind/named.conf.local
          named-checkconf 1>/dev/null


          # /etc/bind/db.conexionlinux.com
          [ "$?" != "0" ] && exit 1 || echo $_etc_bind_db_conexionlinux_com | base64 -d > /etc/bind/db.conexionlinux.com
          [ "$?" != "0" ] && exit 1 || chown root:bind /etc/bind/db.conexionlinux.com
          [ "$?" != "0" ] && exit 1 || chmod 0644  /etc/bind/db.conexionlinux.com
          [ "$?" != "0" ] && exit 1 || mv /etc/bind/db.conexionlinux.com /etc/bind/db.${getDomain}
          [ "$?" != "0" ] && exit 1 || sed -i "s/conexionlinux.com/${getDomain}/g" /etc/bind/db.${getDomain}

          # /etc/bind/db.conexionlinux.com.fwd
          [ "$?" != "0" ] && exit 1 || echo $_etc_bind_db_conexionlinux_com_fwd | base64 -d > /etc/bind/db.conexionlinux.com.fwd
          [ "$?" != "0" ] && exit 1 || chown root:bind /etc/bind/db.conexionlinux.com.fwd
          [ "$?" != "0" ] && exit 1 || chmod 0644  /etc/bind/db.conexionlinux.com.fwd
          [ "$?" != "0" ] && exit 1 || mv /etc/bind/db.conexionlinux.com.fwd /etc/bind/db.${getDomain}.fwd
          [ "$?" != "0" ] && exit 1 || sed -i "s/conexionlinux.com/${getDomain}/g" /etc/bind/db.${getDomain}.fwd

          # /etc/bind/db.conexionlinux.com.rev
          [ "$?" != "0" ] && exit 1 || echo $_etc_bind_db_conexionlinux_com_rev | base64 -d > /etc/bind/db.conexionlinux.com.rev
          [ "$?" != "0" ] && exit 1 || chown root:bind /etc/bind/db.conexionlinux.com.rev
          [ "$?" != "0" ] && exit 1 || chmod 0644  /etc/bind/db.conexionlinux.com.rev
          [ "$?" != "0" ] && exit 1 || mv /etc/bind/db.conexionlinux.com.rev /etc/bind/db.${getDomain}.rev
          [ "$?" != "0" ] && exit 1 || sed -i "s/conexionlinux.com/${getDomain}/g" /etc/bind/db.${getDomain}.rev


      named-checkzone ${getDomain} /etc/bind/db.${getDomain}.fwd 1>/dev/null
      named-checkzone 0.168.192.in-addr.arpa /etc/bind/db.${getDomain}.rev 1>/dev/null

      chown -R root:bind /var/cache/bind

      systemctl restart bind9
      systemctl enable bind9 >/dev/null 2>&1

      # dhclient.conf
      # vim /etc/dhcp/dhclient.conf
      # dhcp client
      # Eliminando asignacion dns automatico del dhcpd para cliente linux
      # send host-name = gethostname();
      # request domain-name-servers
      # Para que dhcpd asigne eth0 pero sin dns :)
      # -----------------------
      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} Setting dhcp client options${endColour}\n"

      # /etc/dhcp/dhclient.conf
      #echo $_etc_dhcp_dhclient_conf | base64 -d > /etc/dhcp/dhclient.conf
      #chown root:root /etc/dhcp/dhclient.conf
      #chmod 0644  /etc/dhcp/dhclient.conf


      # resolv.conf
      # --------------------------------------------------------------------
      [ "$?" != "0" ] && exit 1 || echo $_etc_resolv_conf | base64 -d > /etc/resolv.conf
      [ "$?" != "0" ] && exit 1 || chown root:root /etc/resolv.conf
      [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/resolv.conf

      # squid server
      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} Installing squid servers${endColour}\n"

      [ "$?" != "0" ] && exit 1 || apt-get install squid -y 1>/dev/null
      [ "$?" != "0" ] && exit 1 || mv /etc/squid/squid.conf /etc/squid/squid.conf.default

      # Configuracion
      # 0.- necesita /etc/squid/squid.conf
      # 1.- necesita /etc/squid/squid_access.csv
      # 2.- necesita /etc/squid/url_deny_AllPorns.txt
      # 3.- necesita /etc/squid/url_deny_AllProfiles.txt
      # 4.- ejecutar bash /etc/squid/squid_access.sh


      # 0.- Copiando configuraciones... squid.conf
      [ "$?" != "0" ] && exit 1 || echo $_etc_squid_squid_conf | base64 -d > /etc/squid/squid.conf
      [ "$?" != "0" ] && exit 1 || chown root:root  /etc/squid/squid.conf
      [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/squid/squid.conf

      # 1.- Copiando configuraciones... squid_access.csv
      [ "$?" != "0" ] && exit 1 || echo $_etc_squid_squid_access_csv | base64 -d > /etc/squid/squid_access.csv
      [ "$?" != "0" ] && exit 1 || chown root:root  /etc/squid/squid_access.csv
      [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/squid/squid_access.csv

      # 2.- Copiando configuraciones... url_deny_AllPorns.txt
      [ "$?" != "0" ] && exit 1 || echo $_etc_squid_url_deny_AllPorns_txt | base64 -d > /etc/squid/url_deny_AllPorns.txt
      [ "$?" != "0" ] && exit 1 || chown root:root  /etc/squid/url_deny_AllPorns.txt
      [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/squid/url_deny_AllPorns.txt

      # 3.- Copiando configuraciones... url_deny_AllProfiles.txt
      [ "$?" != "0" ] && exit 1 || echo $_etc_squid_url_deny_AllProfiles_txt | base64 -d > /etc/squid/url_deny_AllProfiles.txt
      [ "$?" != "0" ] && exit 1 || chown root:root  /etc/squid/url_deny_AllProfiles.txt
      [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/squid/url_deny_AllProfiles.txt

      # 4.- Copiando script bash ... squid_access.sh
      [ "$?" != "0" ] && exit 1 || echo $_etc_squid_squid_access_sh | base64 -d > /etc/squid/squid_access.sh
      [ "$?" != "0" ] && exit 1 || chown root:root /etc/squid/squid_access.sh
      [ "$?" != "0" ] && exit 1 || chmod 0755 /etc/squid/squid_access.sh

      [ "$?" != "0" ] && exit 1 || /etc/squid/squid_access.sh 1>/dev/null

      systemctl restart squid
      systemctl enable squid >/dev/null 2>&1

      # apache2 server
      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} Install apache and setting config${endColour}\n"
      [ "$?" != "0" ] && exit 1 || apt-get install apache2 -y 1>/dev/null

      systemctl start apache2
      systemctl enable apache2 >/dev/null 2>&1

      [ "$?" != "0" ] && exit 1 || echo $_etc_mime_types | base64 -d > /etc/mime.types
      [ "$?" != "0" ] && exit 1 || chown root:root /etc/mime.types
      [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/mime.types

      mv /etc/apache2/sites-enabled/000-default.conf /etc/apache2/sites-enabled/000-default.conf.default.bak
      mv /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf.default.bak

      [ "$?" != "0" ] && exit 1 || echo $_etc_apache2_sites_enabled_000_default_conf | base64 -d > /etc/apache2/sites-enabled/000-default.conf
      [ "$?" != "0" ] && exit 1 || chown root:root /etc/apache2/sites-enabled/000-default.conf
      [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/apache2/sites-enabled/000-default.conf

      [ "$?" != "0" ] && exit 1 || echo $_etc_apache2_sites_available_000_default_conf | base64 -d > /etc/apache2/sites-available/000-default.conf
      [ "$?" != "0" ] && exit 1 || chown root:root /etc/apache2/sites-available/000-default.conf
      [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/apache2/sites-available/000-default.conf

      # Creando directorios
      mkdir -p /var/www/${getDomain}/public_html
      mkdir -p /var/www/wpad.${getDomain}/public_html
      mkdir -p /var/www/intranet.${getDomain}/public_html


      # Copiando contenido
      echo $_var_www_conexionlinux_com_public_html_index_html | base64 -d > /var/www/${getDomain}/public_html/index.html
      sed -i "s/conexionlinux.com/${getDomain}/g" /var/www/${getDomain}/public_html/index.html

      echo $_var_www_wpad_conexionlinux_com_public_html_wpad_dat | base64 -d > /var/www/${getDomain}/public_html/wpad.dat
      sed -i "s/conexionlinux.com/${getDomain}/g"  /var/www/${getDomain}/public_html/wpad.dat

      echo $_var_www_wpad_conexionlinux_com_public_html_wpad_dat | base64 -d > /var/www/wpad.${getDomain}/public_html/wpad.dat
      sed -i "s/conexionlinux.com/${getDomain}/g"  /var/www/wpad.${getDomain}/public_html/wpad.dat

      echo $_var_www_wpad_conexionlinux_com_public_html_wpad_dat | base64 -d > /var/www/html/wpad.dat
      sed -i "s/conexionlinux.com/${getDomain}/g"  /var/www/html/wpad.dat

      echo $_var_www_intranet_conexionlinux_com_public_html_index_html | base64 -d > /var/www/intranet.${getDomain}/public_html/index.html
      sed -i "s/conexionlinux.com/${getDomain}/g"  /var/www/intranet.${getDomain}/public_html/index.html



      chmod -R 755 /var/www/


      # Creando virtual host files
      echo $_etc_apache2_sites_available_conexionlinux_com_conf | base64 -d > /etc/apache2/sites-available/${getDomain}.conf
      echo $_etc_apache2_sites_available_wpad_conexionlinux_com_conf | base64 -d > /etc/apache2/sites-available/wpad.${getDomain}.conf
      echo $_etc_apache2_sites_available_intranet_conexionlinux_com_conf | base64 -d > /etc/apache2/sites-available/intranet.${getDomain}.conf

      sed -i "s/conexionlinux.com/${getDomain}/g" /etc/apache2/sites-available/*

      chown -R root:root /etc/apache2/sites-available/

      cd /etc/apache2/sites-available
      a2ensite ${getDomain}.conf 1>/dev/null
      a2ensite wpad.${getDomain}.conf 1>/dev/null
      a2ensite intranet.${getDomain}.conf 1>/dev/null
      #a2ensite 000-default.conf

      echo $_etc_apache2_ports_conf | base64 -d > /etc/apache2/ports.conf
      chown root:root /etc/apache2/ports.conf
      chmod 0644 /etc/apache2/ports.conf

      chown -R www-data:www-data /var/www/

      chmod -R 755 /var/www

      systemctl reload apache2
      systemctl restart apache2
      systemctl enable apache2 >/dev/null 2>&1

      # Install JellyFin
      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} Install JellyFin Media Server${endColour}\n"

      [ "$?" != "0" ] && exit 1 || apt install apt-transport-https ca-certificates gnupg curl git -y 1>/dev/null
      #wget -O - https://repo.jellyfin.org/jellyfin_team.gpg.key | apt-key add - 1>/dev/null
      #echo "deb [arch=$( dpkg --print-architecture )] https://repo.jellyfin.org/debian bullseye main" | tee /etc/apt/sources.list.d/jellyfin.list 1>/dev/null
      [ "$?" != "0" ] && exit 1 || apt-get update -y 1>/dev/null
      [ "$?" != "0" ] && exit 1 || apt-get install jellyfin -y

      systemctl start jellyfin
      systemctl enable jellyfin >/dev/null 2>&1

      # Habilitando crontab log
      [ "$?" != "0" ] && exit 1 || echo $_etc_rsyslog_conf | base64 -d > /etc/rsyslog.conf
      [ "$?" != "0" ] && exit 1 || chown root:root /etc/rsyslog.conf
      [ "$?" != "0" ] && exit 1 || chmod 0644 /etc/rsyslog.conf


      # Firewall scripts
      # -----------------------
      echo -e "${red} *** Preparando firewall scripts ${plain}\n"

      [ "$?" != "0" ] && exit 1 || echo $_root_AllInOne_v7_1_cfg | base64 -d > /root/AllInOne.v7.1.cfg
      [ "$?" != "0" ] && exit 1 || chown root:root /root/AllInOne.v7.1.cfg
      [ "$?" != "0" ] && exit 1 || chmod 0644 /root/AllInOne.v7.1.cfg

      [ "$?" != "0" ] && exit 1 || echo $_root_AllInOne_v7_1_sh | base64 -d > /root/AllInOne.v7.1.sh
      [ "$?" != "0" ] && exit 1 || chown root:root /root/AllInOne.v7.1.sh
      [ "$?" != "0" ] && exit 1 || chmod 0755 /root/AllInOne.v7.1.sh


      # Seteando autoconfiguracion allinone
      [ "$?" != "0" ] && exit 1 || echo $_usr_lib_systemd_system_allinone_service| base64 -d > /usr/lib/systemd/system/allinone.service
      [ "$?" != "0" ] && exit 1 || chown root:root /usr/lib/systemd/system/allinone.service
      [ "$?" != "0" ] && exit 1 || chmod 0664 /usr/lib/systemd/system/allinone.service

      [ "$?" != "0" ] && exit 1 || systemctl enable allinone >/dev/null 2>&1
      echo -n -e "\t${yellowColour}[-]${endColour}${grayColour} I suggest you a reboot !!!${endColour}\n"
      sleep 3
      reboot
}



# Main Function

if [ $(id -u) -eq 0 ]; then

      declare -i parameter_counter=0
      while getopts ":d:n:h:" arg
        do
          case $arg in
              d)  let parameter_counter+=1
                  setFQDN=$OPTARG
                  getHost=$(echo ${setFQDN} |awk -F "." '{print $1}')
                  getDomain=$(echo ${setFQDN} | cut -d '.' -f 2-)
                  ;;
              n) let parameter_counter+=1
                  ;;
              h) helpPanel
                  ;;
          esac
        done

      if [[ $parameter_counter -ne 2 ]]
      then
        helpPanel
      else



        while true; do
          if [ -f /root/.step_install ]; then
              value_step_install=$(cat /root/.step_install) ;
          else
              value_step_install=0
              echo ${value_step_install} > /root/.step_install
          fi

          if [ $value_step_install -eq 0 ]; then dependencies_hardware; echo 1 > /root/.step_install ;fi
          if [ $value_step_install -eq 1 ]; then adaptando_kernel_eth; echo 2 > /root/.step_install ; reboot ;fi
          if [ $value_step_install -eq 2 ]; then local_repository; echo 3 > /root/.step_install; fi
          if [ $value_step_install -eq 3 ]; then dependencies_software; echo 4 > /root/.step_install ;fi
          if [ $value_step_install -eq 4 ]; then install_services; echo 5 > /root/.step_install; reboot ;fi
          if [ $value_step_install -eq 5 ]; then echo "Instalacion exitosa"; echo 5 > /root/.step_install ; exit 0;fi
          sleep 5s
        done

        exit 0
          #dependencies_hardware
          #adaptando_kernel_eth
          #dependencies_software
          #install_services
          #tput cnorm
      fi

else
    echo -e "\n${redColour}[*] No soy root${endColour}\n"
    exit 1
fi
