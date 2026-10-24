# CHANGELOG

## 1.1.0 — 2026-10-24

- rotate 新增 `--passphrase`：轮换生成的新钥匙直接挂口令（1.0.0 只能生成裸钥匙，转手又撞 KV003——狗粮环节自己吃出来的）
- 自测新增第 30 用例：rotate --apply --passphrase 后新钥匙 audit ENC=ok

## 1.0.0 — 2026-10-24

- 首发版本：scan / audit / baseline / rotate 四条子命令
- 不变量体系：I1-I5（永不输出密钥内容与 known_hosts 主机名、扫描只读、rotate 默认 dry-run、路径 ~ 缩写）
- 发现编号 KV001-KV012（HIGH/MED/LOW 三级）
- 自测 30 用例全绿（fixture 全合成密钥）
- 真机狗粮：作者本机 ~/.ssh 审计出 6 findings / 3 HIGH（两把在用私钥无 passphrase + 目录 755 + known_hosts 明文），当期修复 3 项并复验（GitHub SSH 冒烟通过），KV003 两项按轮换三板斧给人修
