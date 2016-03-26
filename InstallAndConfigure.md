#描述了如何安装配置ruijieclient

# 如何安装 #

> ## 从源代码编译并安装程序 ##
    * 一般安装
```
./configure
make
make install
```

> ## 从安装包安装(rpm, deb etc..) ##
> > 直接使用包管理器安装。

# 特定版本配置 #

## 版本：0.8.3 以上 ##

没有配置文件。直接使用命令行参数。请参考 ruijieclient --help


> ## 版本：0.8 到 0.1.1 ##

  * 配置说明

  * 简化启动（可选，如果使用站点上提供的安装包安装，可以跳过这步）
```
sudo chmod 4755 /usr/local/bin/ruijieclient
```
> 这样下次调用ruijieclient就不需要再加sudo了。
  * 生成配置文件模板(第一次使用时)
```
sudo ruijieclient -g
```
  * 编辑配置
```
sudo gedit /etc/ruijie.conf
```
  * 配置文件格式说明
    * xml配置文件（默认）
```
<?xml version="1.0" ?>
<ruijie.conf version="0.1.1"> #配置版本
  <!--This is a sample configuration file of RuijieClient, change it appropriately according to your settings.-->
  <account>
    <Name>123012007078</Name>  #用户名
    <Password>888888</Password>  #密码
  </account>
  <settings>
    <!--0: Standard, 1: Private-->
    <AuthenticationMode>1</AuthenticationMode> #服务器发现包类型 0 标准发现包 1 锐捷私有发现包
    <NIC>eth0</NIC> #网卡设备界面名
    <EchoInterval>4</EchoInterval> #保活延时 单位秒
    <!--IntelligentReconnect: 0: Disable IntelligentReconnect, 1: Enable IntelligentReconnect -->
    <IntelligentReconnect>1</IntelligentReconnect> #智能重连
    <!--AutoConnect: 0: Disable AutoConnect, 1: Enable AutoConnect (only available in gruijieclient) -->
    <AutoConnect>0</AutoConnect> #自动连接
    <!--Fake Version for cheating server-->
    <FakeVersion>3.99</FakeVersion> #版本伪装
    <!--Fake IP for cheating server-->
    <FakeAddress></FakeAddress> #IP地址伪装
    <!--DHCP mode 0: Disable, 1: Enable DHCP before authentication, 2: Enable DHCP after authentication 3: DHCP after DHCP authentication andre-authentication(You should use this if your net env is DHCP)-->
    <DHCPmode>0</DHCPmode> #DHCP认证模式 0 关闭 1 认证前DHCP 2 认证后DHCP
    <!--Add if you don't want ruijieclient to ping the default gateway-->
    <PingHost>4.2.2.2</PingHost> #自动重连使用的测试主机地址
  </settings>
</ruijie.conf>
```
    * ini配置文件（比如用于嵌入式设备）
```
[ruijieclient]
Name=123012007078 #用户名
Password=888888 #密码
#This is settings
#Network Adapter Name 网卡设备界面名
NIC=eth0
#0: Standard, 1: Private 服务器发现包类型 0 标准发现包 1 锐捷私有发现包
AuthenticationMode=1
#保活延时 单位秒
EchoInterval=25
#IntelligentReconnect: 0: Disable IntelligentReconnect, 1: Enable IntelligentReconnect
#智能重连 
IntelligentReconnect=1
#AutoConnect: 0: Disable AutoConnect, 1: Enable AutoConnect (only available in gruijieclient) 
#自动连接
AutoConnect=0
#Fake Version for cheating server
#版本伪装
FakeVersion=3.99
#Fake IP for cheating server
#IP地址伪装
FakeAddress=123.123.123.123
#DHCP mode 0: Disable, 1: Enable DHCP before authentication, 2: Enable DHCP after authentication 3: DHCP after DHCP authentication andre-authentication(You should use this if your net env is DHCP)
#DHCP认证模式 0 关闭 1 认证前DHCP 2 认证后DHCP
DHCPmode=0
#Add if you don't want ruijieclient to ping the default gateway
#自动重连使用的测试主机地址
PingHost=202.102.154.3
```

> ## 版本：0.1（已经废弃） ##

  * 安装包安装(rpm, deb etc..)
    * 直接编辑配置
```
gedit /etc/ruijieclient/ruijie.conf
```