ruijieclient

```
我们旨在提供一个稳定、易用、多功能的跨平台开源锐捷认证客户端,可用于 Linux, Mac, BSD 以及嵌入式系统。
```


```
源码已经移动到 `http://github.com/microcai/ruijieclient.git` 使用 git 进行管理 。
```

## 主要功能 ##
  1. 良好的嵌入式特性
  1. 支持静态认证和3种DHCP认证
  1. 支持2种服务器发现包
  1. 支持客户端版本欺骗
  1. 支持伪造IP
  1. 支持智能重连
  1. 支持后台daemon驻留，支持各种自动启动功能
  1. 支持服务器消息读取和转码

## 注意事项 ##
无论是源码安装还是包管理器安装，**请先阅读\*安装配置指南[InstallAndConfigure](InstallAndConfigure.md)**

想了解如何使用RuijieClient，请看用户手册[manual](manual.md)

如果在安装或者使用过程中出现问题，请参看常见问题[FAQ](FAQ.md)

0.8.3 版本支持到 3.6x 以下版本，支持静态IP认证和DHCP认证(beta)。

**注：本项目是社区发起的第三方软件，和星网锐捷公司无关，我们对不当使用造成的后果不负任何责任。**

## 项目动态 ##
当前这个项目还在建设中，项目目标几近完成，我们已经放出了0.8.3 正式版本。

我们的开发计划:[TODO](TODO.md)
  1. 欺骗过客户端完整性验证
  1. 更好得集成于NetworkManager
  1. 多平台下的图形界面支持
  1. 3代码支持 ( 即将发布 )

## 如何贡献 ##
  1. 加入项目，编写代码
    1. 需具有3.30或以下，DHCP环境的\*测试者**1. 需具有3.30以上版本测试环境的\*开发人员**
  1. 帮忙打包，编写相应系统下的编译、使用指南
  1. 在issue中提供bug报告或者是建议（不一定会去实现）

请联系
Cai Wanzhao <microcai  AT fedoraproject PERIOD org>

Alexander Yang  < iAlexanderYang AT gmail.com>

## 致谢 ##
  1. 测试： Andy Feng <shengfeng2008 AT gmail PERIOD com>, Song Kai <songkam AT gmail PERIOD com>
  1. 打包： Liang Suilong <liangsuilong AT gmail PERIOD com>, Adam Lee <adam8157 AT gmail PERIOD com>

![http://www.gnu.org/graphics/lgplv3-147x51.png](http://www.gnu.org/graphics/lgplv3-147x51.png) 我们传递自由，而非枷锁。
