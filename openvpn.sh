#!/bin/bash
#
function set_ntp(){
	setenforce 0
	sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/selinux/config
	yum -y install ntp
	service ntpd restart
	cp -rf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	cd /root
	echo '0-59/10 * * * * /usr/sbin/ntpdate -u cn.pool.ntp.org' >> /tmp/crontab.back
	crontab /tmp/crontab.back
	systemctl restart crond
}
#获取公网ip，设置共享密钥
function set_shell_input1() {
	clear	
	sqladmin=lc3360001
	yum install lynx -y
	public_ip=`lynx --source www.monip.org | sed -nre 's/^.* (([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'`
	ike_passwd=ezioximliu
yum install network-tools -y
}
function set_openvpn3(){
	modprobe tun
	yum -y install openssl openssl-devel lzo openvpn easy-rsa
	yum -y install expect
cp -rf /usr/share/easy-rsa/ /etc/openvpn
cd /etc/openvpn/easy-rsa/3.0
./easyrsa init-pki 
expect<<-END
spawn ./easyrsa build-ca nopass
expect "CA]:"
send "\r"
expect eof
exit
END
expect<<-END
spawn ./easyrsa gen-req server nopass
expect "server]:"
send "\r"
expect eof
exit
END
expect<<-END
spawn ./easyrsa sign server server
expect "details:"
send "yes\r"
expect eof
exit
END
./easyrsa gen-dh 
touch /etc/openvpn/server.conf
cat >>  /etc/openvpn/server.conf <<EOF
port 1194 # default port
proto udp # default protocol
dev tun
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
reneg-sec 0
ca /etc/openvpn/easy-rsa/3.0/pki/ca.crt
cert /etc/openvpn/easy-rsa/3.0/pki/issued/server.crt
key /etc/openvpn/easy-rsa/3.0/pki/private/server.key
dh /etc/openvpn/easy-rsa/3.0/pki/dh.pem
#plugin /usr/share/openvpn/plugin/lib/openvpn-auth-pam.so /etc/pam.d/login # 如果使用freeradius，请注释这一行
plugin /etc/openvpn/radiusplugin.so /etc/openvpn/radiusplugin.cnf # 如果使用freeradius，请去掉这一行的注释
server 10.8.0.0 255.255.255.0 # 分配给VPN客户端的地址范围
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1"
push "route 192.168.0.0 255.255.255.0"    #指定VPN客户端访问你服务器的内网网段
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 2 20
comp-lzo
persist-key
persist-tun
status openvpn-status.log
log-append openvpn.log
verb 3
#script-security 3
#auth-user-pass-verify /etc/openvpn/checkpsw.sh via-env
client-cert-not-required            #启用后，就关闭证书认证，只通过账号密码认证
username-as-common-name
EOF
touch /etc/openvpn/easy-rsa/3.0/client.ovpn
cat >>  /etc/openvpn/easy-rsa/3.0/client.ovpn <<EOF
client
dev tun
proto udp
remote $public_ip 1194 # – Your server IP and OpenVPN Port
resolv-retry infinite
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
ca ca.crt
auth-user-pass
comp-lzo
reneg-sec 0
verb 3
EOF
}
function set_openvpn_freeradius9(){
	yum -y install libgcrypt libgcrypt-devel gcc-c++
	cd /tmp
	wget http://180.188.197.212/down/radiusplugin_v2.1a_beta1.tar.gz
	tar xzvf radiusplugin_v2.1a_beta1.tar.gz
	rm -rf radiusplugin_v2.1a_beta1.tar.gz
	cd radiusplugin_v2.1a_beta1
	make
	cp -rf radiusplugin.so /etc/openvpn/
	cp -rf radiusplugin.cnf /etc/openvpn/
	sed -i "s/name=192.168.0.153/name=127.0.0.1/g" /etc/openvpn/radiusplugin.cnf
	sed -i "s/sharedsecret=testpw/sharedsecret=testing123/g" /etc/openvpn/radiusplugin.cnf
	systemctl restart openvpn@server
}
function set_iptables10(){
	echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
	sysctl -p
	yum -y install iptables-services
	systemctl start iptables.service
	chmod +x /etc/rc.local
netcard_name=`ifconfig | head -1 | awk -F ":" '{print$1}'`	
cat >>  /etc/rc.local <<EOF
systemctl start iptables
systemctl start openvpn@server
iptables -F
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 3361 -j ACCEPT
iptables -A INPUT -p tcp --dport 3362 -j ACCEPT
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT 
iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
iptables -A INPUT -p gre -j ACCEPT
iptables -A INPUT -p udp -m policy --dir in --pol ipsec -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1701 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 4500 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
iptables -A INPUT -p esp -j ACCEPT
iptables -A INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -j DROP
iptables -A FORWARD -i ppp+ -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -d 10.0.0.0/24 -j ACCEPT
iptables -A FORWARD -s 10.0.0.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o $netcard_name -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $netcard_name -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o $netcard_name -j MASQUERADE
EOF
}
function set_initvpn(){
netcard_name=`ifconfig | head -1 | awk -F ":" '{print$1}'`
#调整公网IP地址
newPubIP=`lynx --source www.monip.org | sed -nre 's/^.* (([0-9]{1,3}\.){3}[0-9]{1,3}).*$/\1/p'`
   sed -r 's/(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b'/$newPubIP/g -i  /etc/openvpn/easy-rsa/3.0/client.ovpn
echo "==========================================================================
                  Centos7 VPN 安装完成                            
										 
				  以下信息将自动保存到/root/info.txt文件中			
                                                                         
                   openvpn 需要导出的客户端配置文件/etc/openvpn/easy-rsa/3.0/client.ovpn 

                   openvpn 需要导出客户端证书文件 /etc/openvpn/easy-rsa/3.0/pki/ca.crt 

                   openvpn 服务器配置文件/etc/openvpn/server.conf 
==========================================================================" > /root/info.txt
	sleep 3
	cat /root/info.txt
	exit;
}