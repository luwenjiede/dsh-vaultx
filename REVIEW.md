# VaultX (dsh-vaultx v0.2.1) 代码审查与优化建议

审查日期：2026-11-11 · 审查范围：main 分支全部 33 个文件（源码逐行阅读 + 测试实跑 + 缺陷探针验证）
审查副本：`vaultx-review/`（经 GitHub API 获取，git 直连 TLS 失败）

## 总体评价

架构成熟度高于一般社区插件：信封加密（改密不重加密）、锁定态一等公民（fail-open）、
注册层+执行层双闸门、AAD 绑定密文位置、哈希链审计、k-匿名泄露检测，设计文档与威胁模型诚实清晰。
测试实跑 **97/97 通过**（需先链接宿主 peer 包，见 D-1）。README 写 88 项已过时。

发现的真实缺陷（均已用实际调用复现，非猜测）按优先级列出。

---

## P0 — 应尽快修复

### P0-1 `store.update()` 绕过 `add()` 的全部安全校验
`lib/store.js` `update()` (L270-289) 与 `add()` (L215-251) 校验不对称，实测：
- `update(id, {env:'PATH'})` 被接受 —— 非法 env 名绕过 `/^DSH_[A-Z0-9_]{3,}$/`（注入面：污染任意环境变量名）；
- `update(id, {sensitivity:'high'})` 后 env 字段保留 —— `add()` 明令禁止 high+env，update 却放行
  （运行时 resolve 会拒 high，但元数据不变量已破坏，且面板/CLI 行为不一致）；
- update 不检查 envField 是否存在。
**建议**：抽出 `validateEntryMeta({env, envField, sensitivity, fields})` 供 add/update 共用；update 升 high 时强制剥离 env/envField。

### P0-2 模型可创建 `sensitivity:'high'` 条目 → 自我锁死
`vaultx_add` 接受 high；而所有模型工具对 high 隐身 → 模型存入后**永远无法 set/delete/list 它**，
条目变成孤儿（只能人工去面板清理）。实测确认。
**建议**：`vaultx_add`/`vaultx_generate` 拒绝 `sensitivity:'high'`（提示模型 high 是人工专用通道），或创建时降级为 normal 并注明。

### P0-3 env 变量名允许重复，resolve 静默 last-wins
两条目同设 `env:'DSH_DUP'` 均被接受（实测）；`resyncEnv()` 的 variables 对象后者覆盖描述，
`resolve()` 按 entries 顺序后者覆盖值 —— **模型可能拿到错误凭据且无任何警告**。
**建议**：add/update 时拒绝已占用的 env 名（或面板显式提示冲突）；resolve 遇冲突写一条审计。

### P0-4 passphrase 词表与声明不符，熵虚标
`lib/generate.js` L22 注释称 "EFF short list, 1296 → trimmed 1000"，实测词表 **698 词、含 1 个重复（697 唯一）**。
实际每词熵 9.44 bits（重复词还引入分布偏差），4 词 passphrase ≈ 37.8 bits + 2 位数字 ≈ 44 bits，
而 `strength.js` 按字符池估算会给出更高的 bits —— 用户被误导。
**建议**：换成完整 EFF short list（1296）或 large list（7776），去重；`vaultx_generate` 返回的
strengthBits 对 passphrase 改用 `words × log2(词表大小)` 的真实生成熵。

### P0-5 SECURITY.md 承诺的「剪贴板 30 秒自清理」未实现
SECURITY.md 限制#3 写明"30 秒内自行清理"，`lib/client.js` 三处 `navigator.clipboard.writeText` 
均无清理逻辑（grep 0 命中）。安全文档失实比没有文档更危险。
**建议**：复制后 `setTimeout(() => navigator.clipboard.writeText(''), 30_000)`（需页面仍在焦点，
做不到就改文档如实描述）；同样核对 `revealRequiresConfirm` 策略位 —— 默认 true 但面板 FieldLine 
reveal 无任何再确认（策略字段成了死配置）。

---

## P1 — 值得做

### P1-1 自动锁定被模型活动无限续命
`touch()` 在每次模型工具调用与每次 shell resolve 时重置 idle 计时器。一个持续活动的会话
（或注入攻击定时调 `vaultx_list`）可让 vault 永不自动锁定。
**建议**：区分 operator activity 与 model activity；auto-lock 只由操作员动作续命，模型活动不重置（或单独给更短的 model-idle 窗口）。

### P1-2 元数据完整性未认证
AAD 只保护字段值的位置绑定；`title/env/sensitivity/tags` 是明文且不进任何 MAC。
拿到文件写权限的攻击者（威胁模型外，但也是误操作/损坏面）可把 high 改 normal、把 env 名调包。
**建议**：unlock 时用 VK 对 `JSON.stringify(规范化元数据)` 计算一个 HMAC 存 header 或每条目，
save 时更新、load/verifyVault 时校验 —— 零依赖成本很低，`vaultx verify` 顺带覆盖。

### P1-3 importVault 缺少结构校验
`index.js` L462 只查 `header` 和 `Array.isArray(entries)`；条目内部 fields 形状、sensitivity 枚举、
env 规则全不验（P0-1 的校验函数正好复用）。`Entry` 的 `Object.assign(this, raw)` 对导入的
`__proto__` 键会触发实例原型 setter（影响限于实例，但应 `Object.create(null)` 或逐键白名单拷贝）。
**建议**：导入时逐条 normalise + 全字段试解密（verifyVault 逻辑），失败即拒绝整份导入。

### P1-4 审计链的跨进程分叉
`AuditLog` 串行队列是**进程内**的；CLI 与宿主同时 append 同一 `audit.log` 时仍会读到相同 tail → prev 相同 → 链分叉
（注释里自己记录过 retool 竞态，队列只修了进程内一半）。
**建议**：append 前用 `fs.open(path,'a+')` + flock（或 lockfile 重试）做跨进程互斥；这也是 ARCHITECTURE §9 单进程假设的最小补丁。

### P1-5 `vaultx_get` 的掩码策略对短密钥偏宽
`mask.js`：13 字符值暴露 head 4 + tail 2（近乎一半）。API key 前缀常见 `sk-` 无妨，但短 token 泄露面偏大。
**建议**：head/tail 各 ≤ 3 且总暴露 ≤ 长度 1/4；≤16 字符全掩码。

### P1-6 `__notes__` 出现在 summary().fields
实测 `summary().fields` 含 `__notes__`；工具层 list 手动滤掉了，但面板 list、CLI、search 各自为政。
**建议**：在 `summary()` 源头过滤保留字段名，消费方不必各自记得。

---

## P2 — 打磨与工程化

- **D-1 开发体验**：fresh clone 后 `pnpm install && pnpm test` 直接红（peer 包不落 node_modules，实测 3 个文件 ERR_MODULE_NOT_FOUND）。
  加一个 `scripts/link-peers.mjs`（从 `DSH_PEER_ROOT` 或检测 dsh 安装目录 symlink），README 写明；或把 peer 加进 devDependencies。
  本次审查即靠手动 symlink 宿主包后 97 全绿。
- **D-2 CI**：仓库无任何 CI。加 GitHub Actions：node 20/22/24 矩阵跑 `node --test`（纯密码学测试不需要 peer，可拆 `test:core` 与 `test:host` 两档）。
- **D-3 文档同步**：README「88 项测试」→ 97；`generate.js` 词表注释；SECURITY.md 剪贴板条款（见 P0）。
- **D-4 client.js 无加载自打日志**：宿主侧有 `note('plugin loaded')`，client 侧 apply() 没有 —— 按本工作区守护规则，UI 插件应在 client apply 里 `console.log("vaultx: client plugin loaded")`，加载页排障时一眼定位。
- **D-5 rotate 后旧 VK buffer 未清零**：`changeMasterPassword` 直接替换 `this.vk`，旧 unwrap 出的 buffer 不清零（`lock()` 有 fill(0)，这里没有）。一致性问题，补一行。
- **D-6 CLI rotate 的密码来源优先级**：`readPassword` env 优先于 `--password`，`vaultx rotate <old> <new>` 在 env 设了旧密码时 argv old 被忽略——行为对但反直觉，help 里写明。
- **D-7 `readTailLine` 边界**：末行 >64KiB 时返回截断行 → prev 算错 → 假断链。当前 detail 限 500 字符不会触发，但 import 的 detail 无限制；给 append 的 detail 统一截断即可。
- **D-8 npm 发布**：README 安装仍走 github:；发布到 npm（`files` 白名单已就绪）+ 版本 tag，配合 D-2 CI 一起做。

## 亮点（保持）

- 信封加密 + check token + 改密只重包裹，测试锁死性质 —— 教科书级。
- `apply()` 永不抛错的锁定态启动，符合本容器「UI 卡死无备用通道」的血泪约束。
- `vaultx_generate` 生成即入库不回显；工具结果「无明文」硬断言测试。
- 双闸门（注册层存在性 + 执行层实时策略）与 `checkModelAccess` 纯函数全矩阵测试。
- k-匿名 fail-open 且显式 `source:'offline'`，不装作查过。
- 三处 `save()` 遗漏的历史修复都写了 dated 注释 —— 好习惯，继续保持。

## 验证记录

- 第一轮审查时：`npm test` 97 pass / 0 fail（Node v24.22.2，symlink 宿主 peer 后）；缺陷探针 P0-1/2/3/4、P1-6 均以真实库调用复现。
- 修复后（第二轮）：`npm test` **121 pass / 0 fail**（新增 hardening/generate/mask 三份回归测试）；`node scripts/link-peers.mjs` 5/5 linked；CLI `help/create/add/get --mask/verify` 全链路冒烟通过；浏览器面板实际渲染未验证（审查副本未安装进 profile，遵守只读边界）。
- 交付：分支 `vaultx-hardening` → PR #1（https://github.com/luwenjiede/dsh-vaultx/pull/1）。

---

## 修复记录（2026-11-11 第二轮，全量修复）

全部 P0/P1/D 项已修复，并锁进回归测试（**121 项全绿**，含新增 `test/hardening.test.mjs`、`test/generate.test.mjs`、`test/mask.test.mjs`）：

| 项 | 修复 |
|---|---|
| P0-1 | `store.update()` 与 `add()` 共用 `validateEntryMeta()`；升 high 自动剥离 env；字段名/环境名/重复 env 同权拦截 |
| P0-2 | `vaultx_add` 拒绝 `sensitivity:'high'` 并返回操作员指引 |
| P0-3 | env 名全局唯一（add/update/import 三处同一函数拦截） |
| P0-4 | 完整 EFF short list 1296 词（`lib/wordlist.js`，CC-BY-3.0）；`generationBits()` 回报真实生成熵；顺带修了 `SETS` 易混淆字符排除名不副实的 bug（lower 含 i/o、upper 含 L） |
| P0-5 | `copySecret()` 30 秒清回剪贴板（仅当值未变，绝不覆盖其后复制的内容）；`revealRequiresConfirm` 面板开关真正接入 `setPolicy`；逐字段明文显示前弹窗 |
| P1-1 | auto-lock 只由操作员活动续命（模型工具调用 / env resolve / pre-execute gate 均不再 touch） |
| P1-2 | 每条目 `metaMac`（HMAC 域分离）；`verifyVault()` 输出 metadata 校验结果；legacy 条目 save 时回填 |
| P1-3 | `sanitizeDocument()` 全结构消毒 + null-prototype 字段表 + `__proto__` 拦截；gateway `importVault` 与 CLI `import` 均先完整试解密再落盘 |
| P1-4 | 审计 append 加跨进程 mkdir 锁文件（stale 超时接管），CLI 与宿主并发写不分叉 |
| P1-5 | 掩码收紧：≤16 字符全掩；长值 head/tail 各 ≤3 且总暴露 ≤ 长度 1/4 |
| D-1 | `scripts/link-peers.mjs` + `pnpm peers` |
| D-2 | `.github/workflows/test.yml`（core 矩阵 node 20/22/24 + host 全量） |
| D-3 | README/SECURITY/ARCHITECTURE 同步（88→121、词表来源、剪贴板条款如实描述） |
| D-4 | client `apply()` 自打 `vaultx: client plugin loaded` |
| D-5 | `changeMasterPassword`/`unlock`/`exportWrapped` 后旧 MK/VK buffer `fill(0)` |
| D-6 | CLI rotate env 优先级写进 help；argv 与 env 不一致时显式报错 |
| D-7 | 审计 `detail`/`title` 入链前截断（2000/300），杜绝超长记录造成的假断链 |

验证：`npm test` 121 pass / 0 fail（Node v24.22.2）；`scripts/link-peers.mjs` 在 fresh clone 可独立运行。