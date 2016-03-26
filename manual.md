#描述了如何使用RuijieClient

从 0.8.3 版本开始，ruijieclient 不再使用配置文件，一切配置都从命令行读取

## 查看命令行参数帮助 ##

在终端中输入
```
ruijieclient --help
```
在终端中看到显示结果
```
-D		DO NOT fork as a daemon
    --daemon	run as a daemon(default)
    --dhcpmode	dhcpmode, by default is 0
		0: disable
		1: DHCP before auth
		2: DHCP after auth
                3: dhcp-authenticate and re-authenticate after DHCP
-k, --kill	kill all RuijieClient daemon
-n, --nic	specify an identifier of net adapter
    --noconfig	do not read config from file
-p, --passwd	specify password
    --pinghost	the host to be pinged(by default is your default gateway).
		RuijieClient uses this to detect network state
    --try	Try number of times of reconnection,-1 = infinite
-u, --user	specify user name
-v, --version	show the version of RuijieClient
```
## 帮助说明 ##
```
-D		不在后台驻留为一个daemon
    --daemon	后台驻留为一个daemon（默认）
    --dhcpmode	指定DHCP模式，默认为0。
		0: 关闭
		1: 认证前DHCP
		2: 认证后DHCP
		3: 先认证，然后DHCP，然后在DHCP认证后再进行一次认证（有的学校是这样）
-k, --kill	杀死所有RuijieClient进程
-n, --nic	指定网卡标识
    --noconfig	指定不从配置文件读取配置（全部从参数获取，没有提供的有默认值）
-p, --passwd	指定密码
    --pinghost	指定测试网络用的主机地址（默认探测默认网关）
    --try	重连测试次数， -1 表示无限次数
-u, --user	指定用户名
-v, --version	显示RuijieClient版本
```
## 部分使用实例 ##
  * 使用网卡 eth0 用户名 cai 密码 cai 登录
```
sudo ruijieclient -n eth0 -u cai -p cai
```
> > 文件将生成在'/etc/ruijie.conf'
  * 如何不以daemon运行？这样我可以保留一个终端窗口直接控制登出。
```
sudo ruijieclient -D -n eth0 -u cai -p cai
```
  * 如何登出？
    * 以默认daemon方式运行
```
sudo ruijieclient -k
```
> > 或者向程序发送SIGINT(3)信号。
    * 以非Deamon方式认证
> > 可以按键盘上的ctrl+c，或者向程序发送SIGINT(3)信号。

  * 不通过网关测试网络连通性，使用自定义的地址（比如 4.2.2.2 一个美国的DNS服务器）

> _因为有些学校，没有经过认证，网关也可以Ping得通。_
```
sudo ruijieclient --pinghost 4.2.2.2  -n eth0 -u cai -p cai
```
  * 使用认证后DHCP方式认证
```
sudo ruijieclient --dhcpmode 2  -n eth0 -u cai -p cai
```
  * 限制网络测试次数为3，超过后退出
```
sudo ruijieclient --try 3  -n eth0 -u cai -p cai 
```