#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#stty erase ^H

#################
#适用于Debian 8+#
#################

#版本
sh_ver=6.8.7
#Github地址
Github_U='https://raw.githubusercontent.com/rockneters/v2raybor/master'
#脚本名
SCRIPT_N='tvb.sh'
#脚本目录
CUR_D='/root'

#颜色information
green_font(){
	echo -e "\033[32m\033[01m$1\033[0m\033[37m\033[01m$2\033[0m"
}
red_font(){
	echo -e "\033[31m\033[01m$1\033[0m"
}
white_font(){
	echo -e "\033[37m\033[01m$1\033[0m"
}
yello_font(){
	echo -e "\033[33m\033[01m$1\033[0m"
}
Info=`green_font [information]` && Error=`red_font [error]` && Tip=`yello_font [Notice]`

#检查whether  for root用户
[ $(id -u) != '0' ] && { echo -e "${Error} You must start with rootuser runs this script "; exit 1; }
#判断current 文件夹whether  for root文件夹
if [ $(pwd) != $CUR_D ];then
	cp $SCRIPT_N $CUR_D/$SCRIPT_N
	chmod +x $CUR_D/$SCRIPT_N
fi

# system 检测组件
check_sys(){
	clear
	#检查 system 
	Distributor=$(lsb_release -i|awk -F ':' '{print $2}')
	if [ $Distributor == 'Debian' ];then
		release='debian'
	else
		echo -e "${Error} This script only works for Debian system !!!"
		lsb_release -a;exit 1;
	fi
	#检查版本
	Release=$(lsb_release -r|awk -F ':' '{print $2}')
	#进行浮点运算
	Release=$(echo $Release|awk '{if ($1 < 8) print 0;else print 1}')
	if [[ $Release == 0 ]];then
		echo -e "${Error} This script only works for Debian 8+ system !!!"
		lsb_release -a;exit 1;
	fi
	#whether Yes64place system 
	if [[ ! `uname -m` =~ '64' ]];then
		echo -e "${Error} This script only works for $(red_font '64place') system !!!"
		lsb_release -a;exit 1;
	fi
	#renew 脚本
	UPDATE_U="${Github_U}/$SCRIPT_N"
	sh_new_ver=$(curl -s $UPDATE_U|grep 'sh_ver='|head -1|awk -F '=' '{print$2}')
	if [ -z $sh_new_ver ];then
		echo -e "${Error} Failed to detect the latest version！"
		sleep 2s
	elif [[ $sh_new_ver != $sh_ver ]];then
		#wget -qO $SCRIPT_N $UPDATE_U
		curl -sO $UPDATE_U
		exec ./$SCRIPT_N
	fi
}
#获取IP
get_ip(){
	SER_IP=$(curl -s ipinfo.io/ip)
	[ -z $SER_IP ] && SER_IP=$(curl -s http://api.ipify.org)
	[ -z $SER_IP ] && SER_IP=$(curl -s ipv4.icanhazip.com)
	[ -n $SER_IP ] && echo $SER_IP || echo
}
#等待 enter 
get_char(){
	SAVEDSTTY=`stty -g`
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2> /dev/null
	stty -raw
	stty echo
	stty $SAVEDSTTY
}
check_sys
SER_IP=$(get_ip)

#防火墙配置
add_firewall(){
	ufw allow $1
}
del_firewall(){
	ufw delete allow $1
}
uninstall_sheild(){
	#org=$(wget -qO- -t1 -T2 https://ipapi.co/org)
	org=$(curl -s --retry 2 --max-time 2 https://ipapi.co/org)
	if [[ $org =~ 'Alibaba' ]];then
		#Yes阿里云则Uninstall云盾
		curl -O http://update.aegis.aliyun.com/download/uninstall.sh && chmod +x uninstall.sh && ./uninstall.sh
		curl -O http://update.aegis.aliyun.com/download/quartz_uninstall.sh && chmod +x quartz_uninstall.sh && ./quartz_uninstall.sh
		pkill aliyun-service
		rm -rf /etc/init.d/agentwatch /usr/sbin/aliyun-service /usr/local/aegis*
		rm -f uninstall.sh quartz_uninstall.sh
		ufw deny from 140.205.201.0/28
		ufw deny from 140.205.201.16/29
		ufw deny from 140.205.201.32/28
		ufw deny from 140.205.225.183/32
		ufw deny from 140.205.225.184/29
		ufw deny from 140.205.225.192/29
		ufw deny from 140.205.225.195/32
		ufw deny from 140.205.225.200/30
		ufw deny from 140.205.225.204/32
		ufw deny from 140.205.225.205/32
		ufw deny from 140.205.225.206/32
	elif [[ $org =~ 'Tencent' ]];then
		#Yes腾讯云则Uninstall云盾ps aux|grep -i agent|grep -v grep
		/usr/local/qcloud/stargate/admin/uninstall.sh
		/usr/local/qcloud/YunJing/uninst.sh
		/usr/local/qcloud/monitor/barad/admin/uninstall.sh
	fi
}
clean_iptables(){
	iptables -D INPUT 1
	iptables -D INPUT 1
}
ufw_default(){
	#UFWdefault set up
	ufw default deny incoming
	ufw default allow outgoing
	uninstall_sheild
	clear && echo -e "\n${Info}请 enter $(red_font y)"
	ufw allow $ssh_port
	#whether 启用UFWmanage IPV6
	check_ipv6=$(curl -s --retry 2 --max-time 2 ipv6.icanhazip.com)
	if [ -z $check_ipv6 ];then
		sed -i 's/IPV6=yes/IPV6=no/g' /etc/default/ufw
	else
		sed -i 's/IPV6=no/IPV6=yes/g' /etc/default/ufw
	fi
	# enforce 修改配置文件开机 start up
	sed -i 's/ENABLED=no/ENABLED=yes/g' /etc/ufw/ufw.conf
	#UFW开机 start up
	ufw enable
}

#获取各组件Install状态
get_status(){
	if [ -e $CUR_D/.bash_profile ];then
		bbr_status=$(cat $CUR_D/.bash_profile|grep bbr_status|awk -F '=' '{print$2}')
		trojan_status=$(cat $CUR_D/.bash_profile|grep trojan_status|awk -F '=' '{print$2}')
		v2ray_status=$(cat $CUR_D/.bash_profile|grep v2ray_status|awk -F '=' '{print$2}')
		wg_status=$(cat $CUR_D/.bash_profile|grep wg_status|awk -F '=' '{print$2}')
		bt_status=$(cat $CUR_D/.bash_profile|grep bt_status|awk -F '=' '{print$2}')
		ssh_port=$(cat $CUR_D/.bash_profile|grep ssh_port|awk -F '=' '{print$2}')
	fi
}
get_status

#BBR FQInstall函数
install_bbr_fq(){
	#下载 system 字符集
	apt -y install locales
	sed -i 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/g' /etc/locale.gen
	locale-gen en_US.UTF-8
	#definition system 编码
	SYS_LANG='/etc/default/locale'
	echo 'LANG="en_US.UTF-8"' > $SYS_LANG
	echo 'LC_ALL="en_US.UTF-8"' >> $SYS_LANG
	echo 'LANGUAGE="en_US.UTF-8"' >> $SYS_LANG
	chmod +x $SYS_LANG
	#记录SSHport
	ssh_port=$(cat /etc/ssh/sshd_config|grep 'Port '|awk '{print $2}')
	echo "ssh_port=$ssh_port" > $CUR_D/.bash_profile
	chmod +x $CUR_D/.bash_profile
	#Turn onScript start
	echo "./$SCRIPT_N" >> $CUR_D/.bash_profile
	if [[ $(lsb_release -c|awk -F ':' '{print $2}') != 'buster' ]];then
		#renew 包源
		buster_1U='deb http://deb.debian.org/debian buster-backports main'
		buster_2U='deb-src http://deb.debian.org/debian buster-backports main'
		sources_F='/etc/apt/sources.list'
		echo "$buster_1U" >> $sources_F
		echo "$buster_2U" >> $sources_F
		apt update
	fi
	#InstallBBR FQ
	buster_V=$(apt search linux-image|grep headers|grep buster-backports|grep cloud|head -1|awk -F '/' '{print$1}'|awk -F 'rs-' '{print$2}')
	if [[ `uname -r` != ${buster_V} ]];then
		apt -y install linux-image-${buster_V}
		apt -y install linux-headers-${buster_V}
	fi
	sed -i '2ibbr_status=false' $CUR_D/.bash_profile
	echo -e "${Info}Orthodox 重启VPS(请稍后自行重新 connectionSSH)..."
	reboot
}
#BBR FQ启用函数
finish_bbr_fq(){
	#Uninstall全部加速
	remove_all(){
		sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
		sed -i '/fs.file-max/d' /etc/sysctl.conf
		sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
		sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
		sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
		sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
		sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
		sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
		sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
		sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
		sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
		sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
	}
	#启用BBR FQ
	if [[ `lsmod|grep bbr|awk '{print $1}'` != 'tcp_bbr' ]]; then
		remove_all
		echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
		echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
		sysctl -p
	fi
	#Uninstall多余Kernel
	Core_ARY=($(dpkg -l|grep linux-image|awk '{print $2}'))
	Cur_Core="linux-image-$(uname -r)"
	for ele in ${Core_ARY[@]};do
		if [ $ele != $Cur_Core ];then
			apt -y remove --purge $ele
		fi
	done
	#renew  system 引导
	update-grub2
	clear && echo
	white_font 'It has been installed\c' && green_font 'BBR-FQ\c' && white_font 'Kernel！BBR-FQ start up\c'
	if [[ `lsmod|grep bbr|awk '{print $1}'` == 'tcp_bbr' ]]; then
		green_font '成功！\n'
	else
		red_font 'fail！\n'
	fi
	#第二行插入BBR FQ状态
	sed -i 's/^bbr_status.*/bbr_status=true/' $CUR_D/.bash_profile
	sleep 2s
	apt update
	apt -y install jq lsof unzip expect resolvconf autoconf
	apt --fix-broken install
	#Change  system 时间并防止重启失效
	#cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	timedatectl set-timezone Asia/Shanghai
	hwclock -w
	#InstallUFW防火墙manage program
	apt -y install ufw
	#UFWdefault set up
	ufw_default
	ufw reload
	if [[ `ufw status` =~ 'inactive' ]];then
		clear && echo -e "\n${Error}防火墙 start upfail！"
		echo -e "${Info}请手动执行命令：ufw enable && ufw reload && ./$SCRIPT_N"
		exit 1
	else
		exec $CUR_D/.bash_profile
	fi
}
#Install并启用BBR FQ
if [ -z $bbr_status ];then
	install_bbr_fq
elif [ $bbr_status == 'false' ];then
	finish_bbr_fq
fi

#域名解析检测
check_domain(){
	clear && echo
	read -p "${Info}请 enter  already 成功解析到本机的域名：" domain
	PING_T=$(ping -c 1 $domain|awk -F '(' '{print $2}'|awk -F ')' '{print $1}'|sed -n '1p')
	if [[ $PING_T != $SER_IP ]];then
		echo -e "${Error}该域名并未解析成功！请检查后重试！"
		sleep 2s && check_domain
	fi
}
#InstallTrojan
TROJAN_U="https://git.io/trojan-install"
install_trojan(){
	if [ -z $trojan_status ];then
		check_domain
		add_firewall 80
		add_firewall 443
		ufw reload
		source <(curl -sL $TROJAN_U)
		sed -i '2itrojan_status=true' $CUR_D/.bash_profile
		trojan_status='true'
		clear && echo
		trojan info
		echo -e "${Info}可访问$(green_font https://${domain})进入网页面板，Press any key to continue..."
		char=`get_char`
	else
		clear && echo
		bash <(curl -sL $TROJAN_U)
		sleep 2s
	fi
	get_status
	manage_trojan
}

#V2Ray用户informationgenerate 
general_v2ray_user_info(){
	alterId=$[$[RANDOM%3]*16]
	email="$(tr -dc 'A-Za-z' </dev/urandom|head -c8)@163.com"
}
#InstallV2Ray
V2RAY_INFO_P='/etc/v2ray/config.json'
V2RAY_U='https://multi.netlify.com/v2ray.sh'
install_v2ray(){
	if [ -z $v2ray_status ];then
		bash <(curl -sL $V2RAY_U) --zh
		port=$(jq '.inbounds[0].port' $V2RAY_INFO_P)
		add_firewall $port
		clean_iptables
		general_v2ray_user_info
		jq '.inbounds[0].settings.clients[0].email="'${email}'"' $V2RAY_INFO_P >temp.json
		mv -f temp.json $V2RAY_INFO_P
		expect <<-EOF
	set time 30
	spawn v2ray stream
	expect {
		"Choose new" { send "3\n"; exp_continue }
		"Fake domain name" { send "www.bilibili.com\n" }
	}
	expect eof
EOF
		sed -i '2iv2ray_status=true' $CUR_D/.bash_profile
		v2ray_status='true'
		clear && echo
		v2ray info
		echo -e "${Info}V2Ray After installation, press any key to continue..."
		char=`get_char`
	else
		bash <(curl -sL $V2RAY_U) -k
		echo -e "${Info}V2Ray update completed ，Press any key to continue..."
		char=`get_char`
	fi
	get_status
	manage_v2ray
}

#WireGuardInstall文件夹
WG_P='/etc/wireguard'
#speeder2v和udp2rawInstall文件夹
SPD_UDP_P="$WG_P/speed_udp"
#generate 未被占用的port
check_port(){
	while :;do
		TP_P=$(shuf -i 1000-9999 -n1)
		[[ -z `lsof -i:$TP_P` ]] && break
	done
	add_firewall $TP_P >/dev/null
	echo $TP_P
}
# Checkwhether 存在用户文件夹
check_wg_user(){
	cd $WG_P/clients
	i=1
	while :;do
		if [ ! -d client$i ];then
			mkdir client$i
			echo $i
			break
		fi
		i=$((i+1))
	done
}
#WireGuard密钥generate 函数
get_wireguard_key(){
	wg genkey |tee ${1}_pri_k |wg pubkey > ${1}_pub_k
}
#录入本地网关
get_gate(){
	while :;do
		clear && echo
		read -p "${Info}请 enter 你终端的default网关：" default_gate
		[ ! -z $default_gate ] && break
	done
}
#InstallWireGuard
install_wg(){
	if [ -z $wg_status ];then
		#generate WireGuard文件夹
		mkdir -p $WG_P/{key,clients,speed_udp}
		#下载WireGuard
		apt -y install wireguard
		cd $SPD_UDP_P
		#speeder与udp版本
		SPD_V='20200818.1'
		UDP_V='20200818.0'
		#下载udpspeeder和udp2raw
		curl -O https://github.com/wangyu-/UDPspeeder/releases/download/$SPD_V/speederv2_binaries.tar.gz
		curl -O https://github.com/wangyu-/udp2raw-tunnel/releases/download/$UDP_V/udp2raw_binaries.tar.gz
		tar zxvf speederv2_binaries.tar.gz
		tar zxvf udp2raw_binaries.tar.gz
		#产生udpspeeder和udp2raw使用的port
		speed_udp_port=`check_port`
		udp_port=`check_port`
		password=$(tr -dc 'A-Za-z' </dev/urandom|head -c8)
		#允许port转发
		sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
		echo '1'> /proc/sys/net/ipv4/ip_forward
		sysctl -p
		#获取网卡
		eth=$(ls /sys/class/net|awk '/^e/{print}')
		port=`check_port`
		#generate 密钥
		cd $WG_P/key
		get_wireguard_key 's'
		get_wireguard_key 'c1'
		#添加服务端配置
		cat > $WG_P/wg0.conf <<-EOF
[Interface]
PrivateKey = $(cat $WG_P/key/s_pri_k)
Address = 10.0.0.1/24
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $eth -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $eth -j MASQUERADE
ListenPort = $port
DNS = 8.8.8.8
MTU = 1420

[Peer]
PublicKey = $(cat $WG_P/key/c1_pub_k)
AllowedIPs = 10.0.0.2/32
EOF
		#客户端配置文件
		CLE_D="$WG_P/clients/client1"
		mkdir -p $CLE_D
		#获取网关
		get_gate
		cat > $CLE_D/client.conf <<-EOF
[Interface]
PrivateKey = $(cat $WG_P/key/c1_pri_k)
PostUp = route add $SER_IP mask 255.255.255.255 $default_gate METRIC 20
PostDown = route delete $SER_IP
Address = 10.0.0.2/24
DNS = 8.8.8.8
MTU = 1420

[Peer]
PublicKey = $(cat $WG_P/key/s_pub_k)
Endpoint = $SER_IP:$port
AllowedIPs = 0.0.0.0/0, ::0/0
PersistentKeepalive = 25
EOF
		#运行前的准备
		ln -s /usr/bin/resolvectl /usr/local/bin/resolvconf >/dev/null
		systemctl enable systemd-resolved.service
		systemctl start systemd-resolved.service
		# set up开机 start up
		systemctl enable wg-quick@wg0
		#Turn onspeed守护进程
		cat > /etc/systemd/system/speederv2.service <<-EOF
[Unit]
Description=Speederv2 Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
StandardError=journal
ExecStart=$SPD_UDP_P/speederv2_amd64 -s -l0.0.0.0:$speed_udp_port -r127.0.0.1:$port -f10:10 --mode 0
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
		#Turn onudp2raw守护进程
		cat > /etc/systemd/system/udp2raw.service <<-EOF
[Unit]
Description=Udp2raw Service
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
StandardError=journal
ExecStart=$SPD_UDP_P/udp2raw_amd64 -s -l0.0.0.0:$udp_port -r127.0.0.1:$speed_udp_port --raw-mode faketcp -a -k $password
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
		# set up开机 start up
		systemctl enable speederv2.service
		systemctl enable udp2raw.service
		#增加游戏加速配置
		cp $CLE_D/client.conf $CLE_D/game.conf
		sed -i '/Post/d' $CLE_D/game.conf
		sed -i "3iPostUp = mshta vbscript:CreateObject(\"WScript.Shell\").Run(\"cmd /c route add $SER_IP mask 255.255.255.255 $default_gate METRIC 20 & cd /d E:\\\Wireguard\\\udp_speed & start udp2raw_mp.exe -c -l127.0.0.1:8855 -r$SER_IP:$udp_port --raw-mode faketcp -k $password & start speederv2.exe -c -l0.0.0.0:1080 -r127.0.0.1:8855 -f10:10 --mode 0 --report 10\",0)(window.close)" $CLE_D/game.conf
		sed -i "4iPostDown = route delete $SER_IP & taskkill /f /im udp2raw_mp.exe & taskkill /f /im speederv2.exe" $CLE_D/game.conf
		sed -i 's/^Endpoint.*/Endpoint = 127.0.0.1:1080/g' $CLE_D/game.conf
		# start upWireGuard+Speederv2+Udp2raw
		wg-quick up wg0
		systemctl start speederv2.service
		systemctl start udp2raw.service
		sed -i "2iwg_status=$port:$udp_port:$speed_udp_port.$password" $CUR_D/.bash_profile
		wg_status=$port:$udp_port:$speed_udp_port.$password
		cd $CUR_D
		#结束反馈
		clear && echo
		if [[ -n $(wg) ]];then
			echo -e "${Info}WireGuardInstall$(green_font 成功)！"
			echo -e "${Info}用户配置文件在文件夹$(green_font $CLE_D)下！"
			echo -e "${Info}client.conf用来科学上网  game.conf用来加速游戏"
		else
			echo -e "${Error}WireGuardInstall$(red_font fail)！"
			echo -e "${Tip}error内容如下："
			wg-quick up wg0
			echo -e "${Info}Press any key to continue..."
			char=`get_char`
			uninstall_wg
			start_menu
		fi
	else
		clear && echo -e "\n${Info}It has been installedWireGuard！"
	fi
	echo -e "${Info}Press any key to continue..."
	char=`get_char`
}

#Install宝塔面板
BT_U="${Github_U}/install_bt_panel.sh"
install_bt(){
	clear
	if [ -z $bt_status ];then
		bash <(curl -sL $BT_U)
		sed -i '2ibt_status=true' $CUR_D/.bash_profile
		bt_status='true'
		echo -e "\n${Info}BT Panel After installation, press any key to continue..."
		char=`get_char`
	else
		echo -e "\n${Info}It has been installedhave BT Panel,即将跳转到BT Panelmanage 页..."
		sleep 2s
	fi
	get_status
	manage_bt
}

#没have Install的展示information
check_install(){
	NAME=$1
	if [ $NAME == 'Trojan' ];then
		cmd='trojan'
	elif [ $NAME == 'V2Ray' ];then
		cmd='v2ray'
	elif [ $NAME == 'WireGuard' ];then
		cmd='wg'
	else
		cmd='bt'
	fi
	echo -e "${Info}Not installed yet${NAME}!!!"
	read -p "${Info}Whether to install ${NAME}[y/n](default:y)：" num
	[ -z $num ] && num='y'
	[ $num != 'n' ] && install_$cmd
}
#Turn on/close port防火墙
manage_v2ray_port(){
	V2RAY_PORT=($(cat $V2RAY_INFO_P|jq '.inbounds'|jq .[].port))
	for ele in ${V2RAY_PORT[@]};do
		$1 allow $ele
	done
}
#manage Trojan
manage_trojan(){
	add_user_trojan(){
		n=`trojan info|tail -9|head -1|awk -F '.' '{print$1}'`
		read -p "${Info}Number of current users $(red_font $n)，Please enter the number of users to be added (default:1)：" num
		[ -z $num ] && num=1
		for((i=0;i<$num;i++));do
			uuid=$(cat /proc/sys/kernel/random/uuid)
			expect <<-EOF
	set time 30
	spawn trojan add
	expect {
		"Username" { send "\n"; exp_continue }
		"definition password " { send "$uuid\n" }
	}
	expect eof
EOF
		done
		clear && echo
		trojan info|tail -$((num*9))
		echo -e "${Info}Press any key to continue..."
		char=`get_char`
	}
	update_trojan(){
		trojan update
		trojan updateWeb
		echo -e "${Info}Trojan already 成功renew ..."
		sleep 2s
	}
	change_trojan_port(){
		Trojan_config_path='/usr/local/etc/trojan/config.json'
		read -p "${Info} Please enter the port号[443-65535]：" newport
		oldport=$(jq '.local_port' $Trojan_config_path)
		if [ $newport -eq $oldport >/dev/null 2>&1 -o $newport -lt 443 >/dev/null 2>&1 -a $newport -gt 65535 >/dev/null 2>&1 ];then
			echo -e "${Error} enter error！ valid port range ：不 for ${oldport}且[443-65535]..."
			sleep 2s
			clear && echo
			change_trojan_port
		else
			sed -i "s/: ${oldport}/: ${newport}/g" $Trojan_config_path
			trojan restart
			del_firewall $oldport
			add_firewall $newport
			echo -e "${Info}防火墙添加成功！"
			ufw reload
			sleep 2s
		fi
	}
	transport_userfile(){
		white_font "   ————Fat Bobby————\n"
		yello_font '——————方式选择——————'
		green_font ' 1.' '  导出用户'
		green_font ' 2.' '  导入用户'
		yello_font '————————————————————'
		green_font ' 0.' '  返回manage 页'
		yello_font "————————————————————\n"
		read -p "${Info}Please enter the number [0-2](default:1)：" num
		[ -z $num ] && num=1
		clear && echo
		case $num in
			0)
			manage_trojan;;
			1)
			trojan export /root/trojanuserfile
			echo -e "${Info}用户文件 already 导出至$(green_font /root/trojanuserfile)..."
			sleep 2s;;
			2)
			echo -e "${Info}请将用户文件放 for $(green_font /root/trojanuserfile)..."
			trojan import /root/trojanuserfile
			sleep 2s;;
			*)
			echo -e "${Error} Please enter the correct number [0-2]"
			sleep 2s
			transport_userfile;;
		esac
	}
	clear && echo
	if [ -z $trojan_status ];then
		check_install 'Trojan'
	else
		white_font "   ————Fat Bobby————\n"
		yello_font '——————User Management——————'
		green_font ' 1.' '  Add user '
		green_font ' 2.' '  Delete users '
		yello_font '——————information Check——————'
		green_font ' 3.' '   Check Link'
		yello_font '—————Trojan set up—————'
		green_font ' 4.' '  renew trojan'
		green_font ' 5.' '  Change port'
		green_font ' 6.' '  导出(入)用户'
		green_font ' 7.' '  Original management window'
		yello_font '————————————————————'
		green_font ' 8.' '  Return to home page'
		green_font ' 0.' '  Exit script'
		yello_font "————————————————————\n"
		read -p "${Info}Please enter the number [0-8](default:1)：" num
		[ -z $num ] && num=1
		clear && echo
		case $num in
			0)
			exit 0;;
			1)
			add_user_trojan;;
			2)
			trojan del;;
			3)
			trojan info
			echo -e "${Info}Press any key to continue..."
			char=`get_char`;;
			4)
			update_trojan;;
			5)
			change_trojan_port;;
			6)
			transport_userfile;;
			7)
			trojan;;
			8)
			start_menu;;
			*)
			echo -e "${Error} Please enter the correct number [0-8]"
			sleep 2s
			manage_trojan;;
		esac
		manage_trojan
	fi
}
#manage V2Ray
manage_v2ray(){
	show_v2ray_info(){
		v2ray info
		echo -e "${Info}Press any key to continue..."
		char=`get_char`
	}
	change_uuid_v2ray(){
		uuid=$(cat /proc/sys/kernel/random/uuid)
		n=$(jq '.inbounds|length' $V2RAY_INFO_P)
		read -p "${Info}Number of current users $(red_font $n)，Please enter to change UUID User ID [1-$n](default:1)：" num
		[ -z $num ] && num=1
		i=$((num-1))
		uuid_old=$(jq ".inbounds[$i].settings.clients[0].id" $V2RAY_INFO_P|sed 's/"//g')
		sed -i "s#${uuid_old}#${uuid}#g" $V2RAY_INFO_P
		v2ray restart
		clear && echo
		#Change UUID后显示新information
		v2ray info|head -$((12*num))|tail -12
		echo -e "${Info}Press any key to continue..."
		char=`get_char`
	}
	add_user_v2ray(){
		#获取current multi-v2ray版本号
		v2ray_ver=$(echo `v2ray -v`|sed 's,\x1B\[[0-9;]*[a-zA-Z],,g'|awk -F 'til: ' '{print$2}')
		if [[ '3.9.0.1' > $v2ray_ver ]];then
			echo -e "${Info}Updating V2Ray..."
			bash <(curl -sL $V2RAY_U) -k
			clear && echo
		fi
		#Number of current users 
		n=$(jq '.inbounds|length' $V2RAY_INFO_P)
		read -p "${Info}Number of current users $(red_font $n)，Please enter the number of users to be added (default:1)：" num
		[ -z $num ] && num=1
		#循环Add user 
		for((i=0;i<$num;i++));do
			expect <<-EOF
	set time 30
	spawn v2ray add
	expect {
		"Define the port" { send "\n"; exp_continue }
		"Transfer method" { send "3\n"; exp_continue }
		"Fake domain name" { send "www.bilibili.com\n" }
	}
	expect eof
EOF
		done
		#开放port防火墙
		V2RAY_PORT=($(cat $V2RAY_INFO_P|jq '.inbounds'|jq .[].port))
		end=$((n+num))
		for((i=$n;i<$end;i++));do
			general_v2ray_user_info
			jq '.inbounds['$i'].settings.clients[0].email="'${email}'"' $V2RAY_INFO_P|jq '.inbounds['$i'].settings.clients[0].alterId='${alterId}'' >temp.json
			mv -f temp.json $V2RAY_INFO_P
			add_firewall ${V2RAY_PORT[$i]}
			clean_iptables
		done
		ufw reload
		v2ray restart
		clear && echo
		v2ray info|tail -$((12*num+1))
		echo -e "${Info}Press any key to continue..."
		char=`get_char`
	}
	v2ray_del(){
		port_o=($(cat $V2RAY_INFO_P|jq '.inbounds'|jq .[].port))
		v2ray del
		port_n=($(cat $V2RAY_INFO_P|jq '.inbounds'|jq .[].port))
		port=`echo ${port_o[@]} ${port_n[@]}|xargs -n1|sort|uniq -u`
		del_firewall $port
	}
	change_v2ray_port(){
		manage_v2ray_port 'ufw delete'
		v2ray port
		clean_iptables
		manage_v2ray_port 'ufw'
		clear && echo
		show_v2ray_info
	}
	clear && echo
	if [ -z $v2ray_status ];then
		check_install 'V2Ray'
	else
		white_font "    ————Fat Bobby————\n"
		yello_font '———————User Management——————'
		green_font ' 1.' '  Change UUID'
		green_font ' 2.' '  Add user '
		green_font ' 3.' '  Delete users '
		green_font ' 4.' '  Change port'
		yello_font '———————information Check——————'
		green_font ' 5.' '   Check Link'
		green_font ' 6.' '   Check flow'
		yello_font '——————V2Ray set up——————'
		green_font ' 7.' '  Original management window'
		green_font ' 8.' '  Turn onTcpFastOpen'
		yello_font '—————————————————————'
		green_font ' 9.' '  Return to home page'
		green_font ' 0.' '  Exit script'
		yello_font "—————————————————————\n"
		read -p "${Info}Please enter the number [0-9](default:1)：" num
		[ -z $num ] && num=1
		clear && echo
		case $num in
			0)
			exit 0;;
			1)
			change_uuid_v2ray;;
			2)
			add_user_v2ray;;
			3)
			v2ray_del;;
			4)
			change_v2ray_port;;
			5)
			show_v2ray_info;;
			6)
			v2ray stats;;
			7)
			v2ray;;
			8)
			v2ray tfo;;
			9)
			start_menu;;
			*)
			echo -e "${Error} Please enter the correct number [0-9]"
			sleep 2s
			manage_v2ray;;
		esac
		manage_v2ray
	fi
}
#manage WireGuard+Speederv2+Udp2raw
manage_wg(){
	wg_info(){
		cd $WG_P/clients
		CLE_ARY=($(ls -l|grep '^d'|awk '{print$9}'))
		for ele in ${CLE_ARY[@]};do
			echo -e "${Info}${ele}的科学上网配置："
			cat $ele/client.conf
			echo -e "$(red_font [information])${ele}的游戏加速配置："
			cat $ele/game.conf
			echo
		done
		cd $CUR_D
		echo -e "${Info}Press any key to continue..."
		char=`get_char`
	}
	add_user_wg(){
		cd $WG_P/clients
		n=$(ls -l|grep '^d'|wc -l)
		read -p "${Info}Number of current users $(red_font $n)，Please enter the number of users to be added (default:1)：" num
		[ -z $num ] && num=1
		port=$(echo $wg_status|awk -F ':' '{print$1}')
		password=$(echo $wg_status|awk -F '.' '{print$2}')
		udp_port=$(echo $wg_status|awk -F ':' '{print$2}')
		cd $WG_P/key
		for((j=0;j<$num;j++));do
			USR_ID=$(check_wg_user)
			CLE_D="$WG_P/clients/client$USR_ID"
			get_wireguard_key "c$USR_ID"
			get_gate
			cat > $CLE_D/client.conf <<-EOF
[Interface]
PrivateKey = $(cat c${USR_ID}_pri_k)
PostUp = route add $SER_IP mask 255.255.255.255 $default_gate METRIC 20
PostDown = route delete $SER_IP
Address = 10.0.0.$[$USR_ID+1]/24
DNS = 8.8.8.8
MTU = 1420

[Peer]
PublicKey = $(cat s_pub_k)
Endpoint = $SER_IP:$port
AllowedIPs = 0.0.0.0/0, ::0/0
PersistentKeepalive = 25
EOF
			wg set wg0 peer $(cat c${USR_ID}_pub_k) allowed-ips 10.0.0.$[$USR_ID+1]/32
			cp $CLE_D/client.conf $CLE_D/game.conf
			sed -i '/Post/d' $CLE_D/game.conf
			sed -i "3iPostUp = mshta vbscript:CreateObject(\"WScript.Shell\").Run(\"cmd /c route add $SER_IP mask 255.255.255.255 $default_gate METRIC 20 & cd /d E:\\\Wireguard\\\udp_speed & start udp2raw_mp.exe -c -l127.0.0.1:8855 -r$SER_IP:$udp_port --raw-mode faketcp -k $password & start speederv2.exe -c -l0.0.0.0:1080 -r127.0.0.1:8855 -f10:10 --mode 0 --report 10\",0)(window.close)" $CLE_D/game.conf
			sed -i "4iPostDown = route delete $SER_IP & taskkill /f /im udp2raw_mp.exe & taskkill /f /im speederv2.exe" $CLE_D/game.conf
			sed -i 's/^Endpoint.*/Endpoint = 127.0.0.1:1080/g' $CLE_D/game.conf
		done
		wg-quick save wg0
		clear && echo
		wg_info
	}
	del_user_wg(){
		cd $WG_P/clients
		CLE_ARY=($(ls -l|grep '^d'|awk '{print$9}'|sed s'/client//g'))
		echo -e "${Info}current 用户序号 for ："
		echo ${CLE_ARY[@]}
		read -p "${Info}请 enter 上面出现的序号(default:1)：" USR_ID
		[ -z $USR_ID ] && USR_ID=1
		wg set wg0 peer $(cat $WG_P/key/c${USR_ID}_pub_k) remove
		wg-quick save wg0
		rm -rf client$USR_ID
		rm -f $WG_P/key/c$USR_ID*
		cd $CUR_D
		echo -e "${Info}用户 already 删除！"
		sleep 2s
	}
	clear && echo
	if [ -z $wg_status ];then
		check_install 'WireGuard'
	else
		white_font "   ————Fat Bobby————\n"
		yello_font '——————User Management——————'
		green_font ' 1.' '  Add user '
		green_font ' 2.' '  Delete users '
		yello_font '——————information Check——————'
		green_font ' 3.' '   Check配置'
		yello_font '————————————————————'
		green_font ' 4.' '  Return to home page'
		green_font ' 0.' '  Exit script'
		yello_font "————————————————————\n"
		read -p "${Info}Please enter the number [0-4](default:1)：" num
		[ -z $num ] && num=1
		clear && echo
		case $num in
			0)
			exit 0;;
			1)
			add_user_wg;;
			2)
			del_user_wg;;
			3)
			wg_info;;
			4)
			start_menu;;
			*)
			echo -e "${Error} Please enter the correct number [0-4]"
			sleep 2s
			manage_wg;;
		esac
		manage_wg
	fi
}
#manage BT Panel
manage_bt(){
	clear && echo
	if [ -z $bt_status ];then
		check_install '宝塔面板'
	else
		bt
	fi
	sleep 2s
	manage_bt
}

#UninstallTrojan
uninstall_trojan(){
	clear && echo
	if [ -z $trojan_status ];then
		echo -e "${Info}Not installed yetTrojan!!!"
	else
		bash <(curl -sL $TROJAN_U) --remove
		del_firewall 80
		del_firewall 443
		ufw reload
		sed -i '/trojan_status/d' $CUR_D/.bash_profile
		unset trojan_status
		echo -e "${Info}Trojan Uninstall complete！"
	fi
	sleep 2s
}
#UninstallV2Ray
uninstall_v2ray(){
	clear && echo
	if [ -z $v2ray_status ];then
		echo -e "${Info}Not installed yetV2Ray!!!"
	else
		manage_v2ray_port 'ufw delete'
		#开始Uninstall
		bash <(curl -sL $V2RAY_U) --remove
		sed -i '/v2ray_status/d' $CUR_D/.bash_profile
		unset v2ray_status
		echo -e "${Info}V2Ray Uninstall complete！"
	fi
	sleep 2s
}
#UninstallWireGuard
uninstall_wg(){
	clear && echo
	if [ -z $wg_status ];then
		echo -e "${Info}Not installed yetWireGuard!!!"
	else
		#close WireGuardport防火墙
		WG_PORT=($(echo $wg_status|awk -F '.' '{print$1}'|sed 's/:/ /g'))
		for ele in ${WG_PORT[@]};do
			ufw delete allow $ele
		done
		#close WireGuard相关进程
		wg-quick down wg0
		systemctl stop speederv2.service
		systemctl stop udp2raw.service
		apt -y remove wireguard
		rm -rf $WG_P
		sed -i '/wg_status/d' $CUR_D/.bash_profile
		unset wg_status
		echo -e "${Info}WireGuard Uninstall complete！"
	fi
	sleep 2s
}
#Uninstall宝塔面板
uninstall_bt(){
	clear && echo
	if [ -z $bt_status ];then
		echo -e "${Info}Not installed yet宝塔面板!!!"
	else
		/etc/init.d/bt stop && chkconfig --del bt
		rm -f /etc/init.d/bt && rm -rf /www/server/panel /www/*
		del_firewall '20,21,80,443,888,8888/tcp'
		del_firewall '20,21,80,443,888,8888/udp'
		ufw reload
		sed -i '/bt_status/d' $CUR_D/.bash_profile
		unset bt_status
		echo -e "${Info}宝塔面板 Uninstall complete！"
	fi
	sleep 2s
}

# set upSSHport
set_ssh(){
	# enter 要Change 的SSHport
	while :;do
		clear && echo
		read -p "${Info} Please enter the SSHport(default:$ssh_port)：" SSH_PORT
		[ -z $SSH_PORT ] && SSH_PORT=$ssh_port
		if [ $SSH_PORT -eq 22 >/dev/null 2>&1 -o $SSH_PORT -gt 1024 >/dev/null 2>&1 -a $SSH_PORT -lt 65535 >/dev/null 2>&1 ];then
			break
		else
			echo -e "${Error} enter error！ valid port range ：22,1025~65534"
			sleep 2s
		fi
	done
	if [ $SSH_PORT != $ssh_port ];then
		#开放安全权限
		if type sestatus >/dev/null 2>&1 && [ $(getenforce) != "Disabled" ]; then
			semanage port -a -t ssh_port_t -p tcp $SSH_PORT
		fi
		#修改SSHport
		sed -i "s/.*Port ${ssh_port}/Port ${SSH_PORT}/g" /etc/ssh/sshd_config
		#Change SSHport防火墙策略
		add_firewall $SSH_PORT
		del_firewall $ssh_port
		ufw reload
		#修改SSHport记录
		sed -i "s/^ssh_port.*/ssh_port=${SSH_PORT}/g" $CUR_D/.bash_profile
		sed -i "s/$SER_IP:$ssh_port/$SER_IP:$SSH_PORT/g" $CUR_D/.bash_profile
		#重启SSH
		service ssh restart
		#close 安全权限
		if type semanage >/dev/null 2>&1 && [ $ssh_port != '22' ]; then
			semanage port -d -t ssh_port_t -p tcp $ssh_port
		fi
		ssh_port=$SSH_PORT
		clear && echo -e "\n${Info} Has been SSHport change into ：$(red_font $SSH_PORT)"
		echo -e "\n${Info} Press any key Return to home page..."
		char=`get_char`
	else
		echo -e "${Info}SSHport Unchanged，current SSHport for ：$(green_font $ssh_port)"
		sleep 2s
	fi
	start_menu
}
# set upRoot password 
set_root(){
	clear && echo
	#获取旧 password 
	pw=`grep "${ssh_port}:" $CUR_D/.bash_profile |awk -F ':' '{print$3}'`
	if [[ -n $pw ]];then
		echo -e "${Info}Your original password is ：$(green_font $pw)"
		read -p "${Info}whether Change root password [y/n](default:n)：" num
		[ -z $num ] && num='n'
	fi
	if [ $num != 'n' ];then
		#generate 随机 password 
		pw=$(tr -dc 'A-Za-z0-9!@#$%^&*()[]{}+=_,' </dev/urandom |head -c 17)
		echo root:${pw} |chpasswd
		sed -i "/$SER_IP/d" $CUR_D/.bash_profile
		sed -i "2i#$SER_IP:$ssh_port:$pw" $CUR_D/.bash_profile
		#启用root password 登陆
		sed -i '1,/PermitRootLogin/{s/.*PermitRootLogin.*/PermitRootLogin yes/}' /etc/ssh/sshd_config
		sed -i '1,/PasswordAuthentication/{s/.*PasswordAuthentication.*/PasswordAuthentication yes/}' /etc/ssh/sshd_config
		#重启ssh服务
		service ssh restart
	fi
	echo -e "\n${Info}Your current password Yes：$(red_font $pw)"
	echo -e "${Tip}Be sure to record your password ！Then any key Return to home page..."
	char=`get_char`
	start_menu
}
# set up防火墙
set_firewall(){
	get_single_port(){
		read -p "${Info}请 enter port[1-65535](default:80)：" port
		[ -z $port ] && port=80
	}
	get_multi_port(){
		echo -e "${Tip}多port enter 格式：$(green_font 21,22,80,443,8888)"
		read -p "${Info}请 enter port[1-65535](default:$(green_font 21,22,80,443,8888))：" port
		[ -z $port ] && port='21,22,80,443,8888'
	}
	open_single_port(){
		get_single_port
		add_firewall $port
		echo -e "${Info}防火墙添加成功！"
	}
	open_multi_port(){
		get_multi_port
		ufw allow $port/tcp
		ufw allow $port/udp
		echo -e "${Info}防火墙添加成功！"
	}
	close_single_port(){
		get_single_port
		ufw deny $port
		echo -e "${Info}防火墙close 成功！"
	}
	close_multi_port(){
		get_multi_port
		ufw deny $port/tcp
		ufw deny $port/udp
		echo -e "${Info}防火墙close 成功！"
	}
	view_ufw_rules(){
		ufw status
		echo -e "${Info}防火墙规则如上，Press any key to continue..."
		char=`get_char`
		set_firewall
	}
	reset_ufw(){
		echo -e "${Info}请 enter $(red_font y)"
		ufw reset
		ufw_default
		echo -e "${Info}防火墙重置成功！"
	}
	clear
	white_font "\n    ————Fat Bobby————\n"
	yello_font '—————————开放————————'
	green_font ' 1.' '  开放单个port'
	green_font ' 2.' '  开放多个port'
	yello_font '—————————close ————————'
	green_font ' 3.' '  close 单个port'
	green_font ' 4.' '  close 多个port'
	yello_font '—————————————————————'
	green_font ' 5.' '   Check规则'
	green_font ' 6.' '  重置规则'
	yello_font '—————————————————————'
	green_font ' 7.' '  Return to home page'
	green_font ' 0.' '  Exit script'
	yello_font "—————————————————————\n"
	read -p "${Info}Please enter the number [0-6](default:1)：" num
	[ -z $num ] && num=1
	clear && echo
	case $num in
		0)
		exit 0;;
		1)
		open_single_port;;
		2)
		open_multi_port;;
		3)
		close_single_port;;
		4)
		close_multi_port;;
		5)
		view_ufw_rules;;
		6)
		reset_ufw;;
		7)
		start_menu;;
		*)
		echo -e "${Error} Please enter the correct number [0-7]"
		sleep 2s
		set_firewall;;
	esac
	ufw reload
	sleep 2s
	set_firewall
}

#Script startmanage 
start_shell(){
	clear
	white_font "\n    ————Fat Bobby————\n"
	yello_font '—————————————————————'
	green_font ' 1.' '  Turn onScript start'
	green_font ' 2.' '  close Script start'
	yello_font '—————————————————————'
	green_font ' 3.' '  Return to home page'
	green_font ' 0.' '  Exit script'
	yello_font "—————————————————————\n"
	read -p "${Info}Please enter the number [0-3](default:3)：" num
	[ -z $num ] && num=3
	case $num in
		0)
		exit 0;;
		1)
		if [[ `grep -c "./$SCRIPT_N" $CUR_D/.bash_profile` -eq '0' ]];then
			echo "./$SCRIPT_N" >> $CUR_D/.bash_profile
		fi
		echo -e "\n${Info}Script start already Turn on！"
		sleep 2s;;
		2)
		sed -i "/$SCRIPT_N/d" $CUR_D/.bash_profile
		echo -e "\n${Info}Script start already close ！"
		sleep 2s;;
		3)
		start_menu;;
		*)
		clear
		echo -e "\n${Error} Please enter the correct number [0-3]"
		sleep 2s
		start_shell;;
	esac
}

#主菜单
start_menu(){
	get_status
	clear
	white_font "\nSuper Vpn One Key Plus $(red_font \[v$sh_ver\])"
	white_font '	 -- Fat Bobby --'
	white_font "      Execute script ：$(green_font ./$SCRIPT_N)"
	white_font "  Terminate ongoing operation ：Ctrl+C\n"
	yello_font '—————————————manage —————————————'
	green_font ' 1.' '  manage Trojan'
	green_font ' 2.' '  manage V2Ray'
	green_font ' 3.' '  manage BT Panel'
	green_font ' 4.' '  manage WireGuard'
	yello_font '—————————————Install—————————————'
	green_font ' 5.' '  Install/renew Trojan(需要域名)'
	green_font ' 6.' '  Install/renew V2Ray (No domain name required)'
	green_font ' 7.' '  InstallWireGuard(游戏加速器)'
	green_font ' 8.' '  InstallBT Panel'
	yello_font '—————————————Uninstall—————————————'
	green_font ' 9.' '  UninstallTrojan'
	green_font ' 10.' ' UninstallV2Ray'
	green_font ' 11.' ' UninstallWireGuard'
	green_font ' 12.' ' UninstallBT Panel'
	yello_font '————————————— system —————————————'
	green_font ' 13.' '  set upSSHport'
	green_font ' 14.' '  set up/ CheckRoot password '
	green_font ' 15.' '  set up防火墙'
	yello_font '——————————————————————————————'
	green_font ' 16.' ' Script startmanage '
	green_font ' 0.' '  Exit script'
	yello_font "——————————————————————————————\n"
	read -p "${Info}Please enter the number [0-16](default:1)：" num
	[ -z $num ] && num=1
	case $num in
		0)
		exit 0;;
		1)
		manage_trojan;;
		2)
		manage_v2ray;;
		3)
		manage_bt;;
		4)
		manage_wg;;
		5)
		install_trojan;;
		6)
		install_v2ray;;
		7)
		install_wg;;
		8)
		install_bt;;
		9)
		uninstall_trojan;;
		10)
		uninstall_v2ray;;
		11)
		uninstall_wg;;
		12)
		uninstall_bt;;
		13)
		set_ssh;;
		14)
		set_root;;
		15)
		set_firewall;;
		16)
		start_shell;;
		*)
		clear
		echo -e "\n${Error} Please enter the correct number [0-16]"
		sleep 2s
		start_menu;;
	esac
	start_menu
}
start_menu