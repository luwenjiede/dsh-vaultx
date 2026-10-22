# dsh-vaultx

**终极密码箱** · The definitive credential vault for [DeepSeek Harness](https://github.com/deepseek-ai)

`scrypt + AES-256-GCM` 信封加密 &nbsp;×&nbsp; 密钥值永不进入模型上下文 &nbsp;×&nbsp; 操作员策略治理 &nbsp;×&nbsp; 哈希链审计

> English below. 中文版在前。

---

## 它是什么

DSH 的设置页里多出一个 **VaultX** 面板：加密存储你的密码、API 密钥、SSH 凭据和 TOTP 验证码。而它的助手（模型）可以**使用**这些凭据——在自己的 shell 命令里写 `$DSH_OPENAI_KEY`，宿主在执行的那一瞬间注入真实值——但**永远看不到**它们的明文：没有任何工具会返回密钥值，任何一条对话记录里都不会出现密码。

这是两个优秀社区插件的基因融合，取长补短（clean-room 重写，不复制源码）：

| 能力 | [dsh-vault](https://github.com/ox0400/dsh-vault) (MIT) | [dsh-key-panel](https://github.com/moruteaven/dsh-key-panel) (Apache-2.0) | **VaultX** |
|---|:---:|:---:|:---:|
| 静态加密（scrypt + AES-256-GCM 信封） | ✅ | ❌ 明文存储 | ✅ |
| 密钥值永不进入模型上下文 | ❌ `vault_get` 返回明文 | ✅ 唯一带外通道是 shell env | ✅ **硬不变量**：无工具返回值 |
| 主密码缺失时优雅启动 | ❌ `apply()` 抛错 → 插件树恢复模式 | ✅ 明文所以无所谓 | ✅ **锁定态启动**，fail-open |
| 高敏感条目人工专用 | ⚠ ask/auto 下仍需确认 | ✅（所有密钥都不给模型） | ✅ **对工具与 $DSH_* 双通道隐身** |
| 操作员四档策略（封存/只读/可写/可编辑） | 三档 | 三档 | ✅ + **注册层与执行层双重闸门** |
| 删除两段式确认（防幻觉误删） | ❌ | ✅ | ✅ |
| 哈希链防篡改审计 | ❌ | 轻量 usage log | ✅ 可校验链 |
| TOTP / 泄露检测(k-匿名) / 生成器 / 强度评估 | ✅ | ❌ | ✅ 全部保留 |
| KDBX 导入 / 浏览器抓取 / CLI 带外取密 | ✅ | ❌ | ✅ CLI（`bin/vaultx.mjs`） |
| 中英双语设置面板 | 部分 | ✅ | ✅ |

**没有采纳的功能**（有意为之，见 [SECURITY.md](SECURITY.md)）：浏览器密码库抓取、KDBX/chrome 全家桶、Playwright 自动填充。核心闭环先做好。

## 安装

```bash
# DSH Web 版（npm 包尚未发布；当前以 GitHub 源安装）
dsh plugin --profile web add github:luwenjiede/dsh-vaultx
```

加载后执行一次 `restart-dsh-web.sh`（或停用再启用；宿主内存缓存插件的 client bundle，刷新页面不重读），设置页出现 **VaultX** 面板。

**首次使用**：面板里设置主密码 → 创建密码箱。推荐用环境变量注入主密码（免打字、免明文进配置）：

```bash
# 1) 0600 权限的 secrets 文件（重启脚本会 source 它）
echo 'export DSH_VAULTX_PASSWORD="你的主密码"' | sudo tee /root/.dsh/secrets/vaultx.env
chmod 600 /root/.dsh/secrets/vaultx.env

# 2) 插件配置：masterPasswordEnv = DSH_VAULTX_PASSWORD
```

没有主密码时插件**照常加载**，vault 呈锁定态；设置页随时候着你解锁。

## 日常工作流

```
助手想调用 OpenAI API：
  1. vaultx_list 看到条目：GitHub / OpenAI ($DSH_OPENAI_KEY) / 阿里云 2FA
  2. 它执行:  curl https://api.openai.com/v1/models -H "Authorization: Bearer $DSH_OPENAI_KEY"
  3. 宿主在 shell 启动前替换真实值；值不进对话、不进事件、不进日志
  4. 审计链多了一条 {model, intent/use, OpenAI} 记录
```

```
你要一个网站的新密码：
  1. 对助手说「帮我生成一个 GitHub 密码，存进密码箱」
  2. vaultx_generate 生成强密码 → 直接加密入库 → 只回传强度统计
  3. 助手永远不知道自己刚生成的是什么值
```

```
你要人工取一个值（带外通道）：
  vaultx get GitHub --field password   # 明文只进你的终端，不经过模型
```

## 安全模型摘要

- **加密**：每条记录每个字段独立 `AES-256-GCM`（新随机 nonce，AAD 绑定 `entryId|field|v1`）。主密码经 `scrypt(N=2^15, r=8, p=1)` 派生密钥，仅用于**包裹随机保险库密钥**——改主密码不重加密数据。落盘 `0600`/目录 `0700`，原子写（tmp+fsync+rename+.bak）。
- **零上下文泄漏**：模型工具**没有任何一条**能返回明文值；`$DSH_*` 注入按次执行、用后即弃。系统提示明确告知模型这一边界。
- **人工专用通道**：`sensitivity: high` 的条目对模型完全隐身，且不参与 `$DSH_*` 注入。
- **两段式删除** + **origin 归属**：模型只能动自己创建（`tags:['model']`）的条目；操作员条目对模型只读引用。
- **防暴力**：错误解锁 5 次锁定 5 分钟（进程内计数）。
- **可验证审计**：JSONL 哈希链；任何删改中间记录都会让 `verify()` 报断点。

完整威胁模型、已知限制与责任边界：[SECURITY.md](SECURITY.md)。架构与取舍的长文：[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## CLI（带外通道，不进对话）

```bash
vaultx create <master-password>
vaultx add  GitHub --field password=... --field username=me
vaultx get  DSH_OPENAI_KEY            # 按 id / 标题 / 环境变量名定位，输出明文
vaultx get  GitHub --mask             # 只要掩码
vaultx env  --mask                    # 列出将注入的 $DSH_* 键值（可掩码）
vaultx gen  --style passphrase --store WiFi
vaultx totp GitHub --uri
vaultx verify                         # 审计链 + 全库可解密自检
vaultx export <target-pw> backup.json / vaultx import backup.json <pw>
```

主密码从 `DSH_VAULTX_PASSWORD` 读取（`--password-env` 可改名），避免出现在 shell 历史。

## 开发

```bash
git clone https://github.com/luwenjiede/dsh-vaultx && cd dsh-vaultx
pnpm install            # 无运行时依赖；peer 由宿主解析
pnpm test               # 88 项：RFC 6238/4226 官方向量、信封往返、防篡改、k-匿名、策略矩阵、工具零泄漏、client 注册契约
```

测试覆盖（全部 `node:test`，零外部框架）：密码学信封与 nonce 唯一性、HOTP/TOTP **RFC 官方向量**、store 原子写与 mode 钉死、policy 全矩阵、审计链断点检测、breach k-匿名（stub fetch，无真网络）、工具行为「无明文」硬断言、client bundle 注册形状与 **Typert wire 形参名逐一对账**。

## 与上游 fork 网络无关

本项目是独立新仓库。它**借鉴** dsh-vault 与 dsh-key-panel 的设计思想并 clean-room 重写，不含二者的任何源码行；二者的许可证原文见各自仓库。

---

# English

**VaultX** is a credential vault plugin for DeepSeek Harness that fuses the strengths of two community plugins and fixes the weak spot of each:

- from **dsh-vault** (Ox0400): serious cryptography — scrypt-wrapped random vault key, AES-256-GCM per-field envelopes, TOTP, HIBP breach checks with proper k-anonymity, a strong generator;
- from **dsh-key-panel** (moruteaven): the zero-context-leak model — secrets are injected into the assistant's shell per execution via `ctx.shellEnv` and **never** returned by any tool, so they never enter the model transcript;
- **fixes**: the vault no longer needs its master password at boot (locked-but-healthy state, fail-open), plaintext is never the storage format, high-sensitivity entries are a hard human-only channel (invisible to tools *and* to `$DSH_*`), every access leaves a hash-chained audit trail, deletes are two-phase, policy gates run both at registration and at call time.

Install: `dsh plugin --profile web add github:luwenjiede/dsh-vaultx`

The model works with `$DSH_*` references; you reveal values only in the settings panel or the CLI. `pnpm test` runs 88 checks including the official RFC 6238 vectors and a "no plaintext in tool results" hard assertion suite.

Threat model & limitations: [SECURITY.md](SECURITY.md) · Design deep-dive: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## License

MIT © 2026 luwenjiede
