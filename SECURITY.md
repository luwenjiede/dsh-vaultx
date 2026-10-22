# VaultX Security Policy / Threat Model

一句话：**VaultX 是加密静态存储 + 零上下文泄漏的凭据管理**。它假设宿主机器属于操作员；它不假设模型可信。

## 信任边界

| 主体 | 信任？ | 说明 |
|---|---|---|
| 操作员（你，浏览器设置页 + 本机文件权限） | ✅ | 唯一能揭示明文、改策略、导出导入的主体。 |
| 助手 / 模型 | ❌ | 只能调用注册表里存在的工具；其权限受「注册层 + 执行层」双闸门约束。**没有任何工具会返回密钥明文。** |
| 提示注入（经工具结果、网页内容、文件内容进入模型的恶意指令） | ❌ 视为攻击者 | 注入面即"模型能做什么"——见下表：值不回传 + high 隐身 + 两段删除 + origin 限制，构成对注入外传的核心抵抗。 |
| 同机同 uid 进程 / root | ❌（不抵抗） | 与一切本地凭据管理器的共同边界：能读你 vault.json + 拿到 env 里的明文密码，就能解密。见「限制」。 |
| VaultX 自身代码 | ✅ 按安装信任 | 它在宿主进程内运行，权限等同宿主。 |

## 密码学

- **信封加密**：随机 256-bit Vault Key（VK）加密每条记录的每个字段：`AES-256-GCM`，每字段独立 96-bit 随机 nonce；AAD = `entryId|fieldName|formatVersion`。
  - 字段间密文不可拼接（AAD 绑定）；nonce 不复用；GCM tag 让"错密钥 / 篡改密文 / 篡改 nonce"一律抛错，绝不吐明文。
- **主密码 → 包裹密钥**：`scrypt(N=32768, r=8, p=1, 16B 随机盐, maxmem 64MiB)` 派生 MK，MK 只加密 VK（wrap/unwrap 同样是 AES-GCM）。
  - 改主密码 = 重新包裹 VK，**数据密文不变**（有测试锁定此性质）。
  - 解锁校验用固定明文 check token（`vaultx-check-v1`）加密后回读；GCM 失败即错密码。错误计数 5 次锁 5 分钟（进程内）。
- **随机源**：全部走 `node:crypto`（`randomBytes`/`scrypt`），生成器用拒绝采样保证字符分布均匀（有偏差测试）。
- **无外部依赖**：`dependencies: {}`。全部密码学来自 Node。

## $DSH_* 通道（核心不变量）

- 宿主 `dsh-shell-env` 注册：仅声明「解锁 + 允许注入 + 非 high」的条目名（`resolve()` 才取值）。
- **值只在单次 shell 执行的进程环境里存在**；执行结束即弃。不写盘、不进事件、不进对话记录。
- `high` 敏感度条目**即使被人工填了 env 字段**（手改文件），声明与解析两侧都会拒绝——测试覆盖。
- 锁定的 vault 不声明任何变量；声明后 vault 再被锁/删文件，resolve 返回空 map，不抛错。

## 模型攻击面（工具层）

注册表随策略模式变化（sealed 下 0 个工具），`tools/pre-execute` 再按**调用时实时策略 + 目标条目元数据**做第二道裁决：

- `reveal` 类（取明文值）：**不存在这种工具**（策略层也硬拒）。
- `high` 条目：list/get/totp/set/delete 一律不可见。
- 写/删：模型只能动自己创建（`tags:['model']`）的条目；操作员条目对模型只读引用。
- 删除两段式：随机一次性确认 token（5 分钟 TTL，内存态，重启作废），单发调用无法摧毁凭据。
- TOTP：默认不注册（注册层收口）+ gate 层再拦。
- `vaultx_generate`：新生成的密钥**直接入库不回显**。
- 系统提示明确告知模型"值不可得"，并指引带外 CLI 路径。

## 审计链

`vaultx/audit.log`：JSONL，每条记录含 `prev`（上一条的 SHA-256）与 `hash`（本条除 hash 字段外的 SHA-256）。`verify()` 从头走链，任何中间行被改/删/插都会报断点。记录只含非机密上下文（actor/action/id/title/字段名/detail）——**设计上不会把值记进去**（有测试断言 reveal 记录里不含明文）。CLI 同样写链。

## 落盘卫生

- 目录 `0700`、文件 `0600`（vault / policy / audit / 导出文件）。
- 写 = 同目录 tmp → `writeFile` → `fsync` → rename，保留一份 `.bak`，崩溃不丢上一版本。
- 标题/标签/字段名是明文元数据（可搜索）——与主流密码库一致；**字段值永不落盘明文**。

## 网络

唯一出网：`api.pwnedpasswords.com`，泄露检测，k-匿名——只发 SHA-1 前 5 字符，本地比对后缀；`Add-Padding: true` 抗旁路流量分析；1h 前缀缓存、12s 超时；**任何网络失败降级为「离线结论」，永不阻塞操作、永不把完整哈希交出去**（测试用 stub fetch 钉死）。
插件本身无遥测、无自动更新、无回连。

## 已知的、明确的限制（也是为什么没有"采纳"某些上游功能）

1. **同 uid 进程可读 vault.json**。若宿主进程被完全攻陷，攻击者可拿到密文，并可能从进程内存或 env 文件拿到主密码 → 解密。对抗此场景需要 OS 级隔离（专用 uid、SELinux/AppArmor、或硬件密钥）。本项目不伪装提供这种保护。
2. **主密码经 settings RPC 一次**（本机 loopback / 受信 web 会话）。它不落任何存储（config 字段 `masterPassword` 存在则视你配置文件为机密——推荐 `masterPasswordEnv`）。
3. **剪贴板**：面板复制值到剪贴板；剪贴板历史是 OS 特性，30 秒内自行清理。
4. **快照**：`vault.json.bak` 是加密的（同信封），但会**无限期保留上一版**——需要空间时可手动删除。
5. **不做的事**：不提供 KDBX/浏览器抓取（二期候选），不做云同步（导入导出已覆盖），不做"零知识托管"（本地单用户工具）。
6. **TOTP 时效**：模型通道开启后，代码会进对话（RFC 6238 码是短时机密；默认关闭正是此因）。
7. **自动锁定**（idle 计时器）：锁定后 shell 注入即停，但已在途的 shell 进程环境不受追溯。

## 漏洞披露 / 版本固定

发现安全问题请开 GitHub issue（公开）或私聊 maintainer。审计基线：npm `dsh-vault@1.10.75`、`@moruteaven/dsh-key-panel@1.0.2` 的 2026-10-22 静态审计（tarball sha512 校验后隔离目录审读，未执行插件代码）。

## Attribution

- 加密与审计思路：学习 [ox0400/dsh-vault](https://github.com/ox0400/dsh-vault)（MIT）的实现方向；
- 零上下文泄漏与策略治理思路：学习 [moruteaven/dsh-key-panel](https://github.com/moruteaven/dsh-key-panel)（Apache-2.0）的 SECURITY.md 威胁模型。
- VaultX 为 clean-room 实现，不含二者源码；二者 LICENSE 归各自作者所有。
