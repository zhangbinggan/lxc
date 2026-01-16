# QFNUScoreReminder

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![GitHub stars](https://img.shields.io/github/stars/W1ndys/QFNUScoreReminder?style=social)
![GitHub forks](https://img.shields.io/github/forks/W1ndys/QFNUScoreReminder?style=social)

**曲阜师范大学教务系统成绩监控**  
检测到新有成绩出来之后会上报

#### 点击链接加入群聊【Easy-QFNU ｜曲师大选课指北群】：https://qm.qq.com/q/xDrtQHMDNm

#### 点击链接加入群聊【Easy-QFNU ｜曲师大选课指北群 2】：https://qm.qq.com/q/Zw6GRHucim
关注微信公众号获取更多内容

![img](https://picx.zhimg.com/80/v2-a42b58d3c6fa27d3ebe03b7090a7cf63.jpeg)
## 效果展示

![效果](https://pica.zhimg.com/80/v2-ab040cb6e2c97cd56de73d09777c4f07.png)

---

## 使用方法

使用教程：[点击这里](https://blog.w1ndys.top/posts/4fee17c4)

### 1. Fork 项目

[W1ndys/QFNUScoreReminder: 曲阜师范大学教务系统成绩监控，检测到新有成绩出来之后会上报](https://github.com/W1ndys/QFNUScoreReminder)

点击链接进入 Github，fork 本项目到自己的仓库。

![Fork 项目](https://pica.zhimg.com/80/v2-01a15518704c6c8af91cf05cd843c795.png)

### 2. 新增钉钉机器人

- 去钉钉新建一个自己的群。
- 进入群设置 > 机器人，添加一个自定义 webhook 机器人。
- 记录配置的 `webhook` 和 `secret`（不要泄露）。

例如，如果你的 webhook 是 `https://oapi.dingtalk.com/robot/send?access_token=xxx` ，那么：

- `DD_BOT_TOKEN` 就是 `xxx`
- `DD_BOT_SECRET` 就是 `secret`

![钉钉机器人](https://pica.zhimg.com/80/v2-99e91c06e71ac28cbed199f9e4321896.png)

### 3. 新增飞书机器人（可选）

- 访问飞书开放平台，创建一个自定义机器人。
- 记录配置的 `webhook` 和 `secret`（不要泄露）。

- `FEISHU_BOT_URL` 就是 `https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxx`
- `FEISHU_BOT_SECRET` 就是验证关键词，自己自定义的

### 4. 配置环境变量

进入设置配置环境变量。

![配置环境变量](https://pica.zhimg.com/80/v2-e24e61d04f7bfdde25ce104f2a016c5d.png)

分别配置以下环境变量：

- `DD_BOT_SECRET` 和 `DD_BOT_TOKEN`：钉钉机器人配置的 `webhook` 和 `secret`
- `FEISHU_BOT_URL` 和 `FEISHU_BOT_SECRET`：飞书机器人配置的 `webhook` 和 `secret`
- `USER_ACCOUNT` 和 `USER_PASSWORD`：教务系统账号密码

### 5. 运行

点击 `Run workflow` 按钮，运行项目。如果配置正确，会收到钉钉和飞书消息。

![运行项目](https://pica.zhimg.com/80/v2-7c49b45057d28dec0b33b9b7b37bc108.png)

收到消息，说明配置成功并且初始化成功。

程序会每 5 分钟检查一次成绩，有新成绩会发送消息。

## 更新日志

### 2025-01-17

- 更新了获取全部学期的总学分和平均绩点
- 更新了计算本学期绩点
- 更新了保存成绩和绩点数据

你可以在 [output.txt](output.txt) 文件中查看成绩和绩点数据。
