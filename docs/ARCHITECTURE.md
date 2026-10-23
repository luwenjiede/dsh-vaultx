# VaultX 架构与设计决策

> 为什么长这样。写给未来的维护者（包括未来的你）。

## 0. 目标

把 DSH 市场上两个密码箱插件的**可取之处合成一个**，把各自的**致命短板修掉**，不另起炉灶地做全家桶：

1. dsh-vault（ox0400）的密码学内核值得继承：scrypt、AES-256-GCM 信封、k-匿名泄露检测、TOTP。
   但它有两个结构性问题：
   - **boot 依赖主密码**：缺密码 → `apply()` 抛错 → cordis 整棵插件树进恢复模式（key-panel 的源码注释明确记录过这个真实故障）；
   - **主密钥直接加密数据**：改主密码必须全库重加密；且 `vault_get` 会把明文密码交回模型上下文。
2. dsh-key-panel（moruteaven）的「零上下文泄漏」是真正先进的模型安全设计：没有任何工具返回值、shell 带外替换、origin 归属、两段删除。
   但它的交换条件：**明文落盘**（"plaintext rather than an encrypted vault"，作者自述为可用性让步）。

VaultX = dsh-vault 的加密 × key-panel 的零泄漏，再修掉 vault 的 boot 脆性与 get 泄漏，修掉 key-panel 的明文存储。

## 1. 信封加密（核心决策 #1）

```
MasterPassword ──scrypt(N=32768,r=8,p=1,salt)──▶ MK ──wrap──▶ VK(随机256-bit) ──AES-256-GCM──▶ 字段密文
```

- 数据只被 **VK** 加密，VK 随机生成、被 **MK** 包裹（wrap 本身也是 AES-GCM + 固定 AAD）。
- **改主密码 = 重新包裹 VK**，所有字段密文一个字节不动（测试 `rotate master password re-wraps VK without re-encrypting fields` 锁死此性质）。这同时把"重加密中途断电丢库"整类风险消掉。
- **check token**：固定明文 `vaultx-check-v1` 加密存头。解锁时 unwrap 失败或 check 验不过 → 错密码，不触碰任何条目；也是防爆破计数器（5 次锁 5 分钟）的判定依据。
- 字段级 AAD = `entryId|fieldName|formatVersion`：密文与"位置"绑定。跨条目搬运密文（把 GitHub 的 password blob 挪到 AWS 的 password 位置）GCM 直接拒绝——有测试专门验这个。
- 为什么不用 argon2id：Node 原生没有，带第三方原生依赖违背"零依赖"。scrypt(N=2^15) 是 OWASP 认可的替代档位（Bitwarden 网页端同档）。

## 2. 锁定态是一等公民（核心决策 #2）

`apply()` **永不抛错**。缺主密码、vault 文件不存在、文件损坏——都进入合法的锁定态：

- 工具照常注册，调用时返回清晰指引（"vault is locked"）；
- `$DSH_*` **不声明任何变量**（registry 的声明=可见性边界）；
- 结构元数据（标题/标签/字段名）可读——与主流密码库一致，支持锁定态搜索；
- 解锁路径：设置面板（Typert remote `unlock`）、`masterPasswordEnv` 启动注入、或永远不解。

这是对 vault「缺密码炸树」和 key-panel「明文才敢启动」两个对立缺陷的同时回答：**可用性不靠牺牲静态加密换**。

## 3. 存入全开、取出有门（核心决策 #3）

三条硬不变量，任何策略档位都不放松：

1. **取出姿态独立成旋钮** `modelReveal: deny/ask/allow`（默认 ask）：list=摘要、get=掩码+强度、generate/add=只回 id 不回值；`vaultx_reveal` 是唯一明文出口，默认每次调用弹人工审批（宿主 waterfall `kind:'ask'`）。
2. **唯一带外通道** = shellEnv `resolve()`：宿主按次执行注入；声明阶段（variables）只有名字与描述，值只在执行瞬间出现在子进程环境里。
3. **`high` 条目人工专用**：对 list/get/totp/set/delete 隐身，且**即使手改文件塞了 env 字段**，resolve 与声明两处都会拒绝（测试覆盖）。

软闸门（操作员可调）：

| 模式 | 注册的工具 | env 注入 |
|---|---|---|
| sealed | 无（连 intent 都不注册） | 停 |
| readonly | list/get/intent（+totp 视开关） | ✅ |
| write | + generate/set（仅 origin=model 可改） | ✅ |
| edit | + delete（两段式确认） | ✅ |

纵深：模式决定**工具存在性**（注册层），`tools/pre-execute` 按调用时实时策略再裁一次（gate 层）——策略改了不用重启插件树也立即生效，且绕过注册层的路径不存在。

`generate` 的设计反转值得单独说：上游两家都把"生成的值"返回给调用方（vault 的生成器回显明文，key-panel 的 set 要求明文入参）。VaultX 的 `vaultx_generate` **生成后直接入库，只回传强度统计**——模型连自己刚生成的秘密都不知道，注入攻击让它"念出来"也无从念起。

## 4. 审计哈希链

JSONL，每条含 `prev`（上一条 SHA-256）与 `hash`（本条除 hash 外全文 SHA-256）。改/删/插任何一行，`verify()` 报断点位置。载荷只含非机密上下文。CLI 与面板共享同一条链——排查"这个密钥到底被动过没有"不靠信任，靠验证。

## 5. 泄露检测的隐私姿势

继承 dsh-vault 的 k-匿名（只发 SHA-1 前 5 字符 + `Add-Padding`），并把它钉成测试：请求 URL 必须只含前缀、完整哈希不得出现、任何网络错误一律降级 `offline`（可用性优先，绝不为查询失败阻塞用户操作，也绝不"失败即判安全"——返回 `source:'offline'` 让调用方知道没查成）。

## 6. 文件卫生

目录 0700、文件 0600（vault/policy/audit/导出），原子写（tmp→fsync→rename→dir fsync）+ `.bak` 保留。锁与主密码都不进盘：策略文件独立、明文只含枚举值。

## 7. 不做的功能，以及为什么

| 功能 | 来源 | 不做的理由 |
|---|---|---|
| KDBX/浏览器/1Password 导入 | dsh-vault | 解析器攻击面大（二进制格式 fuzzing 不是我们的人手能补的）；核心闭环先跑稳 |
| Chrome/Firefox keychain 抓取 | dsh-vault | 把别人的明文密码库吸进我们的库=一次性扩大泄露半径 |
| Playwright 自动填充 | dsh-vault | 依赖 playwright-core peer + 浏览器自动化本身是注入面；二期 |
| 云端同步 | 两家都没有 | 本地工具；导出/导入/信封换密码已覆盖迁移场景 |
| 硬件密钥因子 | — | 同 uid 进程的威胁模型见 SECURITY.md 限制 #1；YubiKey/OTP 硬件化值得做但需要真机验证，不空头承诺 |

## 8. 测试即规格

88 项 `node:test`，没有一项是摆设：RFC 官方向量锁密码学基元；"无明文出现在工具结果" 是对融合核心的机器检验；wire 契约测试逐参对账（Typert 按形参名派生字段、拒绝多余键——这条隐性契约靠手写文档必翻车，靠测试锁死）；locale 测试锁 zh/en 键集一致与扁平化形状。改任何一条不变量，测试红。

## 9. 已知取舍

- **titles 明文**：支持锁定态搜索/列表；值永不明文。与 Bitwarden/KeePass 生态惯例一致。
- **scrypt 内存档 64MiB**：maxmem 保守值，低配容器不至于 OOM；安全性靠 N=2^15 撑。
- **进程内防爆破计数**：重启清零。攻击者拿到文件+能无限试的，本来也已经接近拿到 env 文件了；持久化计数会引入新的状态一致性问题，不值得。
- **单进程假设**：一个宿主一个 vault 实例；同机多宿主共享同一 vault 文件需要跨进程锁（dsh-atomic-write 的 withFileLock 思路），留作二期。
