#FAQ

# 通用版本问题 #

  * 客户端在find server阶段停滞？
> 很有可能是xp关机后将网卡休眠导致(wake on after shutdown)。
> 参考解法http://forum.ubuntu.org.cn/viewtopic.php?t=72737
  * gnome的网络管理器不能保存配置状态？（如IP）
> 请在管理器里面新建一个配置，然后默认它为系统配置。
  * 我可以尝试去静态编译libpcap吗？
> 可以，但是我们不推荐您这么做。根据libpcap官方的通知，静态编译是危险的。

# 特定版本问题 #

## 版本：0.7 ##

  * ./configure 失败，有错误。
> 一般情况下，主要需要 libpcap-devel, libxml2-devel 这2个开发库。

## 版本：0.1.2 ##
  * 认证成功后，却又不断重新认证，但是可以上网
> 这个 bug 我们已经在 SVN 仓库 [r66](https://code.google.com/p/ruijieclient/source/detail?r=66) 最新版里解决了，请使用0.7正式版本解决或者预防这个问题。
  * ./configure 失败，有错误。
> 一般情况下，主要需要 libpcap-devel, libxml2-devel openssl-devel 这3个开发库。

## 版本：0.1.1 ##

  * ./configure 失败，有错误。
> 一般情况下，主要需要 libnet-devel openssl-devel(or libssl-devel), libpcap-devel, libxml2 这4个开发库。

## 版本：0.1 （已经废弃） ##

  * ./configure 失败，有错误。
> 一般情况下，主要需要libnet-devel, openssl-devel(or libssl-devel), libpcap-devel 这3个开发库。