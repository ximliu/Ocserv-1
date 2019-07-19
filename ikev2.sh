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

function set_strongswan2(){
    yum -y install strongswan strongswan-tnc-imcvs strongswan-libipsec
	cd /root/
	touch zhengshu.sh 
cat >> /root/zhengshu.sh <<EOF
#!/bin/bash
strongswan pki --gen --outform pem > ca.key.pem
strongswan pki --self --in ca.key.pem --dn "C=CN, O=Fastvpn, CN=Fastvpn CA" --ca --lifetime 3650 --outform pem > ca.cert.pem
strongswan pki --gen --outform pem > server.key.pem
strongswan pki --pub --in server.key.pem --outform pem > server.pub.pem
strongswan pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in server.pub.pem --dn "C=CN, O=Fastvpn, CN=$public_ip" --san="$public_ip" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem
strongswan pki --gen --outform pem > client.key.pem
strongswan pki --pub --in client.key.pem --outform pem > client.pub.pem
strongswan pki --issue --lifetime 1200 --cacert ca.cert.pem --cakey ca.key.pem --in client.pub.pem --dn "C=CN, O=Fastvpn, CN=$public_ip" --outform pem > client.cert.pem
openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "Fastvpn Client Cert" -certfile ca.cert.pem -caname "Fastvpn CA" -out client.cert.p12 -password pass:
cp -r ca.key.pem /etc/strongswan/ipsec.d/private/
cp -r ca.cert.pem /etc/strongswan/ipsec.d/cacerts/
cp -r server.cert.pem /etc/strongswan/ipsec.d/certs/
cp -r server.key.pem /etc/strongswan/ipsec.d/private/
cp -r client.cert.pem /etc/strongswan/ipsec.d/certs/
cp -r client.key.pem /etc/strongswan/ipsec.d/private/
cat ca.cert.pem >> /etc/raddb/certs/ca.pem
cat server.cert.pem >> /etc/raddb/certs/server.pem
cat server.key.pem >> /etc/raddb/certs/server.key
cat /etc/raddb/certs/server.key >> /etc/raddb/certs/server.pem
EOF
chmod +x /root/zhengshu.sh
echo '' > /etc/strongswan/ipsec.conf
cat >>  /etc/strongswan/ipsec.conf <<EOF
config setup
    uniqueids=never          
conn %default
     keyexchange=ike              #ikev1 或 ikev2 都用这个
     ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
     esp=aes256-sha256,aes256-sha1,3des-sha1!
     auto=start
     closeaction = clear
     dpddelay = 60s        #每60秒向客户发送数据包以检测用户是否在线，不在线则断开！
     dpdtimeout = 120s   #120秒内没收到用户发回的数据包则强制断开！ 
     inactivity = 30m  #30分钟内用户与服务器没有数据交互则强制断开！
     ikelifetime = 8h   #每次连接的最长有效期，超过有效期则自动重新连接
     keyingtries = 3   #连接最大尝试数
     lifetime=1h
     margintime = 5m   #ikelifetime 超时前5分钟重新协商连接，以免被强制断开！
     dpdaction = clear   #清除不响应用户的所有缓存、安全信息，Dead Peer Detection
     left=%any                    #服务器端标识,%any表示任意
     leftsubnet=0.0.0.0/0         #服务器端虚拟ip, 0.0.0.0/0表示通配.
     right=%any                   #客户端标识,%any表示任意
conn IKE-BASE
    leftca=ca.cert.pem           #服务器端 CA 证书
    leftcert=server.cert.pem     #服务器端证书
    rightsourceip=10.0.0.0/24    #分配给客户端的虚拟 ip 段，格式为：单个IP或1.1.1.1-1.1.1.5或1.1.1.0/24
 
#供 ios 使用, 使用客户端证书
conn IPSec-IKEv1
    also=IKE-BASE
    keyexchange=ikev1
    fragmentation=yes         #开启对 iOS 拆包的重组支持
    leftauth=pubkey
    rightauth=pubkey
    rightauth2=xauth-radius  #使用radius
    rightcert=client.cert.pem
    auto=add
 
#供 ios 使用, 使用 PSK 预设密钥
conn IPSec-IKEv1-PSK
    also=IKE-BASE
    keyexchange=ikev1
    fragmentation=yes
    leftauth=psk
    rightauth=psk
    rightauth2=xauth-radius #使用radius
    auto=add
 
#供 使用ikev2 协议连接使用（osx、windows、ios）
conn IPSec-IKEv2
    keyexchange=ikev2
    ike=aes256-sha256-modp1024,3des-sha1-modp1024,aes256-sha1-modp1024!
    esp=aes256-sha256,3des-sha1,aes256-sha1!
    rekey=no
    left=%defaultroute
    leftid=$public_ip
    leftsendcert=always
    leftfirewall=yes
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-radius
    rightsourceip=10.0.0.150-10.0.0.254
    eap_identity=%any
    dpdaction=clear
    fragmentation=yes
    auto=add
 
#供 windows 7+ 使用, win7 以下版本需使用第三方 ipsec vpn 客户端连接
conn IPSec-IKEv2-EAP
    also=IKE-BASE
    keyexchange=ikev2
    #ike=aes256-sha1-modp1024!   #第一阶段加密方式
    rekey=no                     #服务器对 Windows 发出 rekey 请求会断开连接
    leftauth=pubkey
    rightauth=eap-radius
    rightsendcert=never          #服务器不要向客户端请求证书
    eap_identity=%any
    auto=add
#供linux客户端
conn ipke2vpn
    keyexchange=ikev2
    ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,3des-sha1!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%defaultroute
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    leftid=$public_ip
    right=%any
    rightsourceip=10.0.0.0/24
    authby=secret
    rightsendcert=never
    eap_identity=%any
    auto=add
EOF
echo '' > /etc/strongswan/strongswan.conf
cat >>  /etc/strongswan/strongswan.conf <<EOF
# strongswan.conf - strongSwan configuration file
#
# Refer to the strongswan.conf(5) manpage for details
#
# Configuration changes should be made in the included files
charon {
        i_dont_care_about_security_and_use_aggressive_mode_psk = yes
        duplicheck.enable = no
        threads = 16
        compress = yes 
        load_modular = yes
        plugins {
                include strongswan.d/charon/*.conf    
               }
	dns1 = 8.8.8.8
	dns2 = 114.114.114.114
}
include strongswan.d/*.conf
EOF
sed -i "s/# accounting = no/accounting = yes/g" /etc/strongswan/strongswan.d/charon/eap-radius.conf 
#\n是回车 \t tab
sed -i '/servers {/a\ \t radius{\n \t address = 127.0.0.1 \n \t secret = testing123 \n \t \t }' /etc/strongswan/strongswan.d/charon/eap-radius.conf 
sed -i "s/# backend = radius/ backend = radius/g" /etc/strongswan/strongswan.d/charon/xauth-eap.conf
cat >>  /etc/strongswan/ipsec.secrets <<EOF
: RSA server.key.pem #使用证书验证时的服务器端私钥
: PSK $ike_passwd #使用预设密钥时, 8-63位ASCII字符
: XAUTH $ike_passwd
EOF
chmod o+r /etc/strongswan/ipsec.secrets
chmod o+x /etc/strongswan/
}
echo "==========================================================================
                  Centos7 VPN 安装完成                     
                  strongswan VPN 预共享密钥:$ike_passwd 

                   strongswan 证书生成文件/root/zhengshu.sh 

                   strongswan 服务器配置文件/etc/strongswan/ipsec.conf 

                   strongSwan 共享密钥配置文件 /etc/strongswan/ipsec.secrets 

                   strongSwan 客户端DNS配置文件 /etc/strongswan/strongswan.conf

                   strongswan 连接radius密钥配置文件/etc/strongswan/strongswan.d/charon/eap-radius.conf

                   开机启动配置文件/etc/rc.local  
==========================================================================" > /root/info.txt
	sleep 3
	cat /root/info.txt
	exit;
}
