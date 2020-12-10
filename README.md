# ShiroExplore
本项目致力于打造Shiro漏洞检测、验证和攻击一体化的Burpsuite插件平台，达到快速发现，快速利用的目标。

## 功能介绍 
### 扫描发现能力
+ 本查件支持的扫描目前为Shiro-550 两种加密版本的扫描，即1.2.4版本AES-CBC加密、1.4.2版本AES-GCM加密

  对应该插件中模块如下

  Shiro-550 V1 （AES-CBC)

  Shiro-550 V2   (AES-GCM)

+ 被动扫描能力：依赖于Burpsuite插件自动调用进行被动扫描

+ 主动扫描能力:  对应模块应选择ValidKeyFoundBySilent，该功能将发现有效Key

### 漏洞利用能力

- 模块 SearchTomcatEchoGadget ：自动搜索可利用的回显Gadget
- 模块 SilentRCE : 无回显的命令执行
- 模块 TomcatEchoRCE: 有回显的命令执行
- 模块 Getshell ： 反弹shell

### 待开发 TODO:

- 模块SearchSilentGadget：自动搜寻无回显的命令执行Gadget

- 被动扫描Shiro-721 及其他利用方式(部分代码已实现尚未测试)

- 其他功能优化

## 使用说明

### 被动发现

被动发现会如下图出现，无需做任何配置，流量经过Burpsuite后会立即调用插件进行扫描，扫描结果将会提供该漏洞版本、加密方式以及正确的Key值

![image-20201210155925966](C:\Users\Lucifer\AppData\Roaming\Typora\typora-user-images\image-20201210155925966.png)

### 主动发现

如果漏洞存在，日志中将显示有效的Key值

![image-20201210160905621](C:\Users\Lucifer\AppData\Roaming\Typora\typora-user-images\image-20201210160905621.png)



### SilentRCE利用

必须的配置如下图，由于目前暂未支持检索正确的Gadget，请自行尝试可能的Gadget

![image-20201210161339554](C:\Users\Lucifer\AppData\Roaming\Typora\typora-user-images\image-20201210161339554.png)



###  寻找可回显的Gadget 

下图必填项，其中Model 为 SearchTomcatEchoGadget ，如果成功日志中将显示有效的EchoGadget

![image-20201210161924701](C:\Users\Lucifer\AppData\Roaming\Typora\typora-user-images\image-20201210161924701.png)



### 回显利用方式

根据上述搜索到的回显Gadget进行下面的配置，Go以后TomcatEcho栏将会打印回显信息

![image-20201210162312121](C:\Users\Lucifer\AppData\Roaming\Typora\typora-user-images\image-20201210162312121.png)

### Shell 反弹

如下配置，shell地址以ip:port形式给出，目前只支持Linux系统反弹

![image-20201210162540128](C:\Users\Lucifer\AppData\Roaming\Typora\typora-user-images\image-20201210162540128.png)



### 其他

上述展示的均为Shiro550 V1模式，Shiro550 V2 模式同理，仅需改变Attack 中的选项即可，不再说明。

- ## 免责申明

  本项目仅供学习交流使用，请勿用于违法犯罪行为。

  本软件不得用于从事违反中国人民共和国相关法律所禁止的活动，由此导致的任何法律问题与本项目和开发人员无关。

  