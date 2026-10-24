# keyvaultdog 🔑🐕

**SSH key assets hound, in one file.** 把 `~/.ssh` 当资产台账管起来：一把命令清点全部密钥资产、按不变量体系出审计发现、指纹基线 diff、轮换 dry-run。零依赖，只读为默认。

> 灵感来自一次真实自查：机器上有两把**天天在用的私钥没挂 passphrase**，`~/.ssh` 目录权限 755——没有工具指出来，就永远不会有人发现。keyvaultdog 就是那个指出来的工具。

## 为什么需要它

SSH 私钥是大多数工程师**权限最大、管理最松**的资产：

- 磁盘上的私钥大部分没挂 passphrase——笔记本丢 = 全部服务器丢
- `~/.ssh` 目录经常是 755，同机其他用户可以列目录
- 公钥授权满天飞，私钥早删了——「僵尸公钥」没人清理
- 密钥一用多年，轮换永远是「下个季度的事」

keyvaultdog 用一条命令把上面这些变成**带编号、带级别、可 cron 的发现清单**。

## 快速开始

```bash
# 清点 ~/.ssh 全部密钥资产（指纹台账）
python3 keyvaultdog.py scan

# 全量审计（目录/私钥权限、passphrase、僵尸公钥、超龄、known_hosts 明文）
python3 keyvaultdog.py audit
echo $?   # 0=干净 1=有发现 2=用法/运行错误

# 指纹基线：今天存档，明天 diff
python3 keyvaultdog.py baseline save
python3 keyvaultdog.py audit --baseline ~/.keyvaultdog-baseline.json

# 轮换 dry-run（不写任何文件）
python3 keyvaultdog.py rotate --key ~/.ssh/id_ed25519
```

## 四条子命令

| 命令 | 作用 | 退出码 |
|---|---|---|
| `scan` | 指纹台账：每个文件的类型/算法/权限/加密状态/指纹 | 0 |
| `audit` | 台账 + 不变量发现（KV001-KV012，HIGH/MED/LOW） | 0/1/2 |
| `baseline save/show` | 存/看指纹基线，配合 `audit --baseline` 做新增/消失告警 | 0/2 |
| `rotate` | 轮换草案；`--apply [--passphrase PW]` 生成新 ed25519 + 备份，旧钥不动 | 0/2 |

### 发现编号表

| 编号 | 级别 | 含义 |
|---|---|---|
| KV001 | HIGH | key 目录权限放行 group/other（应 700） |
| KV002 | HIGH | 私钥权限放行 group/other（应 600） |
| KV003 | HIGH | 私钥未挂 passphrase——磁盘被偷 = 密钥被偷 |
| KV004 | MED | 私钥超龄（默认 365 天，`--max-age-days` 可调） |
| KV005 | MED | 僵尸公钥：有 `.pub` 没有对应私钥——授权了但钥匙丢了 |
| KV006 | MED | 同类文件出现相同指纹——副本漂移 |
| KV007 | LOW | ssh config 权限过松（应 600） |
| KV008 | LOW | known_hosts 存在明文主机名（`HashKnownHosts yes` 可解决） |
| KV010/011 | MED | 基线 diff：新增/消失的指纹（预期外 = 立刻查） |
| KV012 | LOW | 无法解析的损坏密钥文件 |

## 不变量（这只狗的底线）

- **I1** 永不输出密钥内容——只输出指纹、文件名、权限、计数
- **I2** 永不输出 known_hosts 里的主机名——只输出条目数与明文占比
- **I3** scan/audit/baseline 绝不写扫描目录（基线默认存 `~/.keyvaultdog-baseline.json`）
- **I4** rotate 不带 `--apply` 一个字节都不写；`--apply` 只新增文件，旧钥永不删除
- **I5** 输出路径一律 `~` 缩写

## 放进 cron（每周自查）

```cron
0 9 * * 1  cd /path/to/keyvaultdog && python3 keyvaultdog.py audit --baseline ~/.keyvaultdog-baseline.json >> ~/.keyvaultdog-weekly.log 2>&1
```

有发现时退出码 1，可对接任何告警；`--json` 输出机器可读结果。

## 自测

```bash
python3 selftest.py   # 30 用例，fixture 全部合成密钥，期望 SELFTEST PASS 30/30
```

## 设计边界（一句大实话）

keyvaultdog 是**本机密钥资产的盘点狗**，不是堡垒机：它不管理远端 authorized_keys、不做 ssh-agent、也不能替你完成轮换三板斧里的「去每台主机换授权」——`rotate --apply` 只负责生成新钥匙对和计划，cut over 的三步要人来做。

## License

MIT
