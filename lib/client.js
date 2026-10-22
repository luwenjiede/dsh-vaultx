/**
 * @luwenjiede/dsh-vaultx — client half (browser bundle, hand-written CJS, no build step).
 *
 * Registers a "VaultX" section in the DSH settings page. Talks to the host
 * through the shared connection RPC channel (namespace `vaultx/*`, served by
 * the VaultXGateway Typert remote in ./index.js).
 *
 * Bundle contract (see @deepseek-ai/dsh-client-modules):
 *  - the body only REGISTERS a factory via window.__ModuleLoader__.load({ id, factory });
 *  - the loader id MUST equal the package name;
 *  - seed modules via require(): react, react/jsx-runtime,
 *    @deepseek-ai/dsh-client-ui-primitives;
 *  - `slots`, `locale` and `connection` are cordis SERVICES via inject/ctx.get.
 *
 * Wire contract (see lib/index.js): Typert derives each remote's argument
 * fields from the HOST METHOD's PARAMETER NAMES, and extra keys are rejected.
 * Every `api(...)` call below mirrors the gateway signature exactly — never
 * spread objects into it.
 *
 * Security posture: the panel is the ONLY surface that reveals plaintext
 * values and the only one that can change policy. The model's half
 * (lib/tools.js) can reach neither.
 *
 * @module vaultx/client
 */
window.__ModuleLoader__.load({
  id: "@luwenjiede/dsh-vaultx",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    const react = require("react");
    const { jsx, jsxs, Fragment } = require("react/jsx-runtime");
    const { Button, Input, Tag, StateDot, Modal, Toast } = require("@deepseek-ai/dsh-client-ui-primitives");
    const { useState, useEffect, useCallback, useMemo, useRef } = react;

    const NS = "settings.vaultx";

    /** dsh-client-locale does a single flat object lookup per key — one level
     *  deep (never split('.')). Flatten our grouped dictionaries into dotted
     *  keys ("status.entries") and call them as t("status.entries"). */
    function flat(dict, prefix = "", out = {}) {
      for (const [k, v] of Object.entries(dict)) {
        if (v && typeof v === "object" && !Array.isArray(v)) flat(v, prefix + k + ".", out)
        else out[prefix + k] = v
      }
      return out
    }
    const KINDS = ["login", "api-key", "ssh", "secret", "totp", "custom"]
    const SENS = ["low", "normal", "high"]
    const GEN_STYLES = ["password", "passphrase", "token", "totp"]

    // ─────────────────────────────────────────────────────────────────────
    // Styles — theme variables with fallbacks, motion, focus rings.
    // ─────────────────────────────────────────────────────────────────────
    const STYLE_ID = "vaultx-style";
    function injectStyles() {
      if (typeof document === "undefined" || document.getElementById(STYLE_ID)) return;
      const css = `
.vx-panel { display:flex; flex-direction:column; gap:16px; max-width:920px; }
.vx-card { border:1px solid var(--dsh-border, rgba(128,128,128,.28)); border-radius:14px; padding:14px 16px; background:var(--dsh-bg-elevated, rgba(128,128,128,.05)); }
.vx-card h3 { margin:0 0 10px; font-size:14px; font-weight:600; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.vx-row { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.vx-muted { opacity:.62; font-size:12px; }
.vx-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:10px; }
.vx-entry { border:1px solid var(--dsh-border, rgba(128,128,128,.25)); border-radius:12px; padding:10px 12px; display:flex; flex-direction:column; gap:6px; transition:border-color .15s, box-shadow .15s; animation:vx-in .18s ease-out; }
.vx-entry:hover { border-color: var(--dsh-accent, rgba(109,141,255,.6)); box-shadow:0 1px 8px rgba(0,0,0,.06); }
@keyframes vx-in { from { opacity:0; transform:translateY(3px) } to { opacity:1; transform:none } }
.vx-entry-title { font-weight:600; font-size:13px; word-break:break-all; display:flex; gap:6px; align-items:center; flex-wrap:wrap; }
.vx-fields { display:flex; flex-direction:column; gap:4px; margin-top:2px; }
.vx-field-row { display:flex; align-items:center; gap:6px; font-size:12px; }
.vx-field-name { min-width:78px; opacity:.7; font-weight:500; }
.vx-mask { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; letter-spacing:.5px; user-select:all; }
.vx-badge { border-radius:7px; padding:1px 8px; font-size:11px; border:1px solid var(--dsh-border, rgba(128,128,128,.3)); white-space:nowrap; }
.vx-badge.high { border-color:rgba(225,29,72,.55); color:#e11d48; background:rgba(225,29,72,.06); }
.vx-badge.low { opacity:.6; }
.vx-badge.model { border-style:dashed; opacity:.75; }
.vx-env { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:11px; color:var(--dsh-accent,#6d8dff); word-break:break-all; }
.vx-strength { height:6px; border-radius:3px; background:rgba(128,128,128,.25); overflow:hidden; width:120px; flex:none; }
.vx-strength > i { display:block; height:100%; transition:width .25s ease, background .25s; border-radius:3px; }
.vx-totp { display:flex; flex-direction:column; gap:3px; align-items:flex-start; }
.vx-totp-code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:21px; letter-spacing:4px; font-weight:600; }
.vx-totp-bar { height:4px; width:150px; background:rgba(128,128,128,.25); border-radius:2px; overflow:hidden; }
.vx-totp-bar > i { display:block; height:100%; background:var(--dsh-accent,#6d8dff); transition:width 1s linear; }
.vx-audit { max-height:280px; overflow:auto; font-size:12px; }
.vx-audit table { width:100%; border-collapse:collapse; }
.vx-audit th, .vx-audit td { text-align:left; padding:4px 6px; border-bottom:1px solid var(--dsh-border, rgba(128,128,128,.16)); font-weight:400; white-space:nowrap; }
.vx-audit td.d { white-space:normal; max-width:300px; overflow-wrap:anywhere; }
.vx-audit tr:hover td { background:rgba(128,128,128,.05); }
.vx-actions { display:flex; gap:8px; flex-wrap:wrap; }
.vx-field-edit { display:flex; gap:6px; align-items:center; }
.vx-radio { display:flex; align-items:flex-start; gap:8px; padding:8px 10px; border:1px solid var(--dsh-border, rgba(128,128,128,.25)); border-radius:10px; cursor:pointer; transition:border-color .12s, background .12s; }
.vx-radio:hover { border-color:var(--dsh-accent, rgba(109,141,255,.5)); }
.vx-radio.sel { border-color:var(--dsh-accent,#6d8dff); background:rgba(109,141,255,.08); }
.vx-radio b { font-size:13px; }
.vx-input { flex:1; min-width:120px; }
.vx-danger-note { color:#e11d48; font-size:12px; }
.vx-empty { padding:26px 0; text-align:center; }
.vx-empty svg { opacity:.35; margin-bottom:8px; }
.vx-lockhero { display:flex; flex-direction:column; align-items:center; gap:4px; padding:10px 0 4px; }
.vx-lockhero svg { opacity:.55; }
.vx-seal { font-size:12px; opacity:.6; }
.vxbadge-ok { color:#10b981; } .vxbadge-bad { color:#e11d48; }
@media (prefers-color-scheme: dark) { .vx-badge.high { color:#fb7185; } .vx-danger-note { color:#fb7185; } .vx-entry:hover { box-shadow:0 2px 10px rgba(0,0,0,.35) } }
@media (max-width: 640px) { .vx-grid { grid-template-columns:1fr } }
`;
      const el = document.createElement("style");
      el.id = STYLE_ID;
      el.textContent = css;
      document.head.appendChild(el);
    }

    // ─────────────────────────────────────────────────────────────────────
    // i18n
    // ─────────────────────────────────────────────────────────────────────
    const zh = {
      nav: "VaultX 密码箱",
      lockedTitle: "密码箱已锁定",
      lockedHint: "输入主密码解锁。主密码只用于派生包裹密钥；任何工具永远读不到明文值。",
      password: "主密码", unlock: "解锁", lock: "锁定",
      createTitle: "创建你的密码箱",
      createHint: "设置主密码（≥10 位）。数据加密使用独立随机保险库密钥，修改主密码只重新包裹密钥、不重新加密数据。",
      create: "创建", confirmPassword: "确认主密码", mismatch: "两次输入不一致",
      status: { empty: "尚未创建密码箱", locked: "已锁定", unlocked: "已解锁", entries: "条目", mode: "助手权限" },
      modes: { sealed: "封存", readonly: "只读", write: "可写", edit: "可编辑" },
      policy: "助手权限", policyHint: "无论哪一档，助手永远看不到明文密钥值：它只能在 shell 中引用 $DSH_* 变量，由宿主在执行瞬间注入；高敏感（high）条目对助手完全隐身。删除永远需要两段式确认。",
      autoCapture: "经允许后存储", autoCaptureHint: "允许助手在你明确要求时把凭据存入密码箱（默认关闭）。",
      totpVia: "TOTP 交给助手", totpViaHint: "允许助手计算一次性验证码（短时效机密，默认关闭）。",
      envExport: "$DSH_* 注入", envExportHint: "把标注环境变量的条目按次注入助手 shell；值只存在于那次执行的环境里。",
      entries: "条目", addEntry: "新增条目", editEntry: "编辑条目", deleteEntry: "删除条目",
      deleteConfirm: "确认删除「{title}」？立即生效。",
      kind: "类型", kinds: { login: "登录凭据", "api-key": "API 密钥", ssh: "SSH", secret: "机密", totp: "两步验证", custom: "自定义" },
      sensitivity: "敏感度", sens: { low: "低", normal: "普通", high: "高（人工专用）" },
      envVar: "环境变量", envHint: "DSH_ 开头大写命名；高敏感条目不可注入。", envInvalid: "格式应为 DSH_[A-Z0-9_]{3,}",
      tags: "标签", reveal: "显示", hide: "隐藏", copy: "复制", copied: "已复制，请注意剪贴板安全",
      generator: "生成器", genStyle: "风格", genStyles: { password: "随机密码", passphrase: "口令短语", token: "API 令牌", totp: "TOTP 密钥" },
      genLength: "长度", genWords: "词数", genSymbols: "符号", strength: "强度",
      breach: "泄露检测", breached: "⚠ 出现在公开泄露库", breachOk: "未发现泄露", breachOffline: "离线模式：仅本地库",
      store: "存入密码箱", audit: "审计日志", auditVerify: "校验哈希链",
      auditOk: "链路完整（{n} 条）", auditBroken: "链路断裂于第 {n} 条——文件可能被外部修改",
      at: "时间", actor: "来源", action: "动作", detail: "详情",
      backup: "备份与迁移", export: "导出", exportHint: "导出文件仍是加密信封，仅换包裹密钥的目标密码。",
      exportTarget: "导出目标密码", download: "下载 JSON", import: "导入", importConfirm: "导入将整体替换当前密码箱，确定？",
      rotate: "修改主密码", rotateOld: "当前主密码", rotateNew: "新主密码", doneRotate: "已更新",
      searchPlaceholder: "搜索标题 / 标签 / 环境变量…", empty: "还没有条目",
      addFieldRow: "添加字段", save: "保存", cancel: "取消", close: "关闭",
      titleRequired: "标题必填", modelOrigin: "助手创建", envVarsChip: "注入变量",
      verifyVault: "完整性自检", verifyVaultOk: "全部字段可解密（{n} 条）", verifyVaultFail: "{n} 个字段解密失败",
      intentHint: "助手用 $DSH_* 引用凭据；值不经过对话，也不会出现在任何工具返回里。",
      err: "出错", lockout: "尝试过多，锁定 {n}s", fresh: "全新密码箱",
      masterTooShort: "主密码至少 10 位", fieldNotes: "备注", load: "加载",
      seal: "scrypt + AES-256-GCM 信封加密 · 零值泄漏到模型",
    };
    const en = {
      nav: "VaultX",
      lockedTitle: "Vault is locked",
      lockedHint: "Enter the master password to unlock. It only derives the wrapping key; no tool can ever read plaintext values.",
      password: "Master password", unlock: "Unlock", lock: "Lock",
      createTitle: "Create your vault",
      createHint: "Set a master password (≥10 chars). Data is encrypted under a separate random vault key, so rotation re-wraps instead of re-encrypting.",
      create: "Create", confirmPassword: "Confirm password", mismatch: "Passwords do not match",
      status: { empty: "No vault yet", locked: "Locked", unlocked: "Unlocked", entries: "Entries", mode: "Model access" },
      modes: { sealed: "Sealed", readonly: "Read-only", write: "Writable", edit: "Editable" },
      policy: "Assistant access", policyHint: "In every mode the assistant NEVER sees plaintext values — it references $DSH_* variables the host substitutes at execution time, and high-sensitivity entries stay invisible. Deletes always need two-phase confirmation.",
      autoCapture: "Store on request", autoCaptureHint: "Let the assistant store credentials when you explicitly ask (default off).",
      totpVia: "TOTP for assistant", totpViaHint: "Let the assistant compute one-time codes (short-lived secrets; default off).",
      envExport: "$DSH_* injection", envExportHint: "Inject env-tagged entries per shell execution; values exist only in that execution.",
      entries: "Entries", addEntry: "Add entry", editEntry: "Edit entry", deleteEntry: "Delete entry",
      deleteConfirm: "Delete “{title}”? Takes effect immediately.",
      kind: "Kind", kinds: { login: "Login", "api-key": "API key", ssh: "SSH", secret: "Secret", totp: "2FA", custom: "Custom" },
      sensitivity: "Sensitivity", sens: { low: "Low", normal: "Normal", high: "High (human-only)" },
      envVar: "Env variable", envHint: "Uppercase DSH_* name; high entries cannot be injected.", envInvalid: "must match DSH_[A-Z0-9_]{3,}",
      tags: "Tags", reveal: "Reveal", hide: "Hide", copy: "Copy", copied: "Copied — mind your clipboard",
      generator: "Generator", genStyle: "Style", genStyles: { password: "Password", passphrase: "Passphrase", token: "API token", totp: "TOTP secret" },
      genLength: "Length", genWords: "Words", genSymbols: "Symbols", strength: "Strength",
      breach: "Breach check", breached: "⚠ found in breach data", breachOk: "Not breached", breachOffline: "offline: local list only",
      store: "Store in vault", audit: "Audit log", auditVerify: "Verify chain",
      auditOk: "chain intact ({n})", auditBroken: "chain broken at #{n} — file may be tampered",
      at: "Time", actor: "Actor", action: "Action", detail: "Detail",
      backup: "Backup & migrate", export: "Export", exportHint: "The export stays an encrypted envelope; only the wrapping password changes.",
      exportTarget: "Export target password", download: "Download JSON", import: "Import", importConfirm: "Import replaces the current vault entirely. Continue?",
      rotate: "Rotate password", rotateOld: "Current password", rotateNew: "New password", doneRotate: "Updated",
      searchPlaceholder: "Search title / tags / env…", empty: "No entries yet",
      addFieldRow: "Add field", save: "Save", cancel: "Cancel", close: "Close",
      titleRequired: "title required", modelOrigin: "assistant", envVarsChip: "injected",
      verifyVault: "Integrity check", verifyVaultOk: "all fields decrypt ({n})", verifyVaultFail: "{n} fields failed",
      intentHint: "The assistant references $DSH_* in shell commands; values never traverse the conversation or any tool result.",
      err: "Error", lockout: "too many attempts, locked {n}s", fresh: "fresh vault",
      masterTooShort: "master password must be ≥ 10 chars", fieldNotes: "Notes", load: "load",
      seal: "scrypt + AES-256-GCM envelope · zero values into the model",
    };

    // ─────────────────────────────────────────────────────────────────────
    // Tiny presentational pieces
    // ─────────────────────────────────────────────────────────────────────
    const strengthColor = s => ["#ef4444", "#f97316", "#eab308", "#22c55e", "#10b981"][Math.max(0, Math.min(4, s ?? 0))]
    function StrengthBar({ score, bits }) {
      const pct = [8, 28, 52, 76, 100][Math.max(0, Math.min(4, score ?? 0))]
      return jsxs("span", { className: "vx-row", children: [
        jsx("span", { className: "vx-strength", children: jsx("i", { style: { width: pct + "%", background: strengthColor(score) } }) }),
        bits != null && jsx("span", { className: "vx-muted", children: `${bits} bits` }),
      ] })
    }

    function LockHero() {
      return jsx("div", { className: "vx-lockhero", children:
        jsx("svg", { width: 36, height: 36, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.6, strokeLinecap: "round", children:
          jsxs(Fragment, { children: [
            jsx("rect", { x: 4, y: 10, width: 16, height: 11, rx: 2.5 }),
            jsx("path", { d: "M8 10V7a4 4 0 0 1 8 0v3" }),
            jsx("circle", { cx: 12, cy: 15.5, r: 1.3, fill: "currentColor", stroke: "none" }),
            jsx("path", { d: "M12 17v2" }),
          ] }),
        }) })
    }

    // Reveal/hide/copy one field (operator channel only).
    function FieldLine({ t, api, entryId, name }) {
      const isPlain = ["username", "url", "host", "label"].includes(name)
      const [shown, setShown] = useState(false)
      const [value, setValue] = useState(null)
      const [pending, setPending] = useState(false)

      async function fetchReveal() {
        setPending(true)
        try {
          const r = await (isPlain ? api.masked(entryId, name) : api.reveal(entryId, name))
          setValue(r.ok ? (r.value ?? r.mask) : null)
        } catch { setValue(null) } finally { setPending(false) }
      }
      useEffect(() => { if (shown) fetchReveal() }, [shown])

      if (!shown) {
        return jsxs("span", { className: "vx-field-row", children: [
          jsx("i", { className: "vx-field-name", children: name }),
          jsx(Button, { size: "sm", variant: "ghost", onClick: () => setShown(true), children: t("reveal") }),
        ] })
      }
      return jsxs("span", { className: "vx-field-row", children: [
        jsx("i", { className: "vx-field-name", children: name }),
        jsx("span", { className: "vx-mask", children: value ?? (pending ? "…" : "✕") }),
        !isPlain && jsx(Button, { size: "sm", variant: "ghost", onClick: async () => {
          try { const r = await api.reveal(entryId, name); if (r.ok) await navigator.clipboard.writeText(r.value) } catch { }
        }, children: t("copy") }),
        jsx(Button, { size: "sm", variant: "ghost", onClick: () => { setShown(false); setValue(null) }, children: t("hide") }),
      ] })
    }

    // Live TOTP chip with countdown.
    function TotpChip({ t, api, entryId }) {
      const [state, setState] = useState(null)
      useEffect(() => {
        let dead = false
        const tick = async () => {
          try { const r = await api.totpCode(entryId); if (!dead && r) setState(r) } catch { }
        }
        tick()
        const id = setInterval(tick, 4000)
        return () => { dead = true; clearInterval(id) }
      }, [entryId])
      if (!state) return null
      if (!state.ok) return jsx("span", { className: "vx-muted", children: "—" })
      return jsxs("span", { className: "vx-totp", children: [
        jsxs("span", { className: "vx-row", children: [jsx("span", { className: "vx-totp-code", children: state.code })] }),
        jsx("span", { className: "vx-totp-bar", children: jsx("i", { style: { width: (state.secondsRemaining / 30 * 100) + "%" } }) }),
      ] })
    }

    // Entry editor (operator full power).
    function EntryEditor({ t, api, entry, onClose, onSaved }) {
      const isNew = !entry
      const [form, setForm] = useState(() => ({
        title: entry?.title ?? "", kind: entry?.kind ?? "login", sensitivity: entry?.sensitivity ?? "normal",
        env: entry?.env ?? "", tags: (entry?.tags ?? []).join(", "), notes: entry?.notes ?? "",
      }))
      const [fields, setFields] = useState(() => {
        if (!entry) return { username: "", password: "" }
        return Object.fromEntries(entry.fields.filter(f => !["__notes__"].includes(f)).map(f => [f, ""]))
      })
      const [err, setErr] = useState("")
      const [busy, setBusy] = useState(false)

      const set = k => v => setForm(f => ({ ...f, [k]: v }))
      const secretish = n => /pass|secret|key|token|mfa|totp|code/i.test(n)

      async function fill(name) {
        try {
          const r = await api.generate(secretish(name) && name !== "totp" ? "password" : name === "totp" ? "totp" : "token", 24, 4, true)
          setFields(f => ({ ...f, [name]: r.value }))
        } catch { }
      }

      async function submit() {
        if (!form.title.trim()) { setErr(t("titleRequired")); return }
        if (form.env && !/^DSH_[A-Z0-9_]{3,}$/.test(form.env)) { setErr(t("envInvalid")); return }
        if (form.sensitivity === "high" && form.env) { setErr(t("sens.high") + " ✗ $DSH_*"); return }
        setBusy(true); setErr("")
        const payload = {
          title: form.title.trim(), kind: form.kind, sensitivity: form.sensitivity,
          env: form.env || undefined,
          tags: form.tags.split(",").map(s => s.trim()).filter(Boolean),
          fields: Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== "")),
          notes: form.notes,
        }
        try {
          if (isNew) await api.add(payload.title, payload.kind, payload.sensitivity, payload.env ?? "", "", payload.tags, payload.fields, payload.notes)
          else await api.update(entry.id, { title: payload.title, kind: payload.kind, sensitivity: payload.sensitivity, env: payload.env ?? "", tags: payload.tags, fields: payload.fields, notes: payload.notes })
          onSaved()
        } catch (e) { setErr(String(e?.message ?? e)) } finally { setBusy(false) }
      }

      return jsx(Modal, { open: true, onClose, title: isNew ? t("addEntry") : t("editEntry"), children:
        jsxs("div", { className: "vx-panel", children: [
          jsx(Input, { className: "vx-input", placeholder: "title *", value: form.title, onChange: e => set("title")(e.target.value) }),
          jsxs("div", { className: "vx-row", children: [
            jsxs("label", { className: "vx-row vx-muted", children: [t("kind"), " ",
              jsx("select", { value: form.kind, onChange: e => set("kind")(e.target.value), children: KINDS.map(k => jsx("option", { value: k, children: t("kinds." + k) }, k)) })] }),
            jsxs("label", { className: "vx-row vx-muted", children: [t("sensitivity"), " ",
              jsx("select", { value: form.sensitivity, onChange: e => set("sensitivity")(e.target.value), children: SENS.map(s => jsx("option", { value: s, children: t("sens." + s) }, s)) })] }),
            form.sensitivity === "high" && jsx("span", { className: "vx-danger-note", children: "human-only" }),
          ] }),
          jsxs("div", { className: "vx-row", children: [
            jsxs("label", { className: "vx-row vx-muted", children: [t("envVar"), " ",
              jsx(Input, { style: { width: 190 }, placeholder: "DSH_MY_KEY", value: form.env, onChange: e => set("env")(e.target.value.toUpperCase()) })] }),
            jsxs("label", { className: "vx-row vx-muted", children: [t("tags"), " ",
              jsx(Input, { style: { width: 160 }, placeholder: "work,prod", value: form.tags, onChange: e => set("tags")(e.target.value) })] }),
          ] }),
          Object.entries(fields).map(([name, value]) => jsxs("div", { className: "vx-field-edit", children: [
            jsx(Input, { style: { width: 130 }, value: name, placeholder: "field", onChange: e => setFields(f => { const n = {}; for (const [k, v] of Object.entries(f)) n[k === name ? e.target.value : k] = v; return n }) }),
            jsx(Input, { type: !secretish(name) ? "text" : "password", className: "vx-input", value, placeholder: name, onChange: e => setFields(f => ({ ...f, [name]: e.target.value })) }),
            secretish(name) && jsx(Button, { size: "sm", variant: "ghost", onClick: () => fill(name), children: t("generator") }),
            jsx(Button, { size: "sm", variant: "ghost", onClick: () => setFields(f => { const n = { ...f }; delete n[name]; return n }) }, name + "-x"),
          ] }, name)),
          jsxs("div", { className: "vx-row", children: [
            jsx(Button, { size: "sm", variant: "ghost", onClick: () => setFields(f => ({ ...f, ["custom" + (Object.keys(f).length + 1)]: "" })), children: t("addFieldRow") }),
          ] }),
          jsx(Input, { as: "textarea", rows: 2, placeholder: t("fieldNotes") ?? "notes", value: form.notes, onChange: e => set("notes")(e.target.value) }),
          err && jsx("div", { className: "vx-danger-note", children: err }),
          jsxs("div", { className: "vx-actions", children: [
            jsx(Button, { variant: "primary", disabled: busy, onClick: submit, children: t("save") }),
            jsx(Button, { variant: "outline", disabled: busy, onClick: onClose, children: t("cancel") }),
          ] }),
        ] }) })
    }

    // Standalone generator with strength + breach and one-click store.
    function Generator({ t, api, onClose, onStored }) {
      const [style, setStyle] = useState("password")
      const [length, setLength] = useState(24)
      const [words, setWords] = useState(4)
      const [symbols, setSymbols] = useState(true)
      const [res, setRes] = useState(null)
      const [breach, setBreach] = useState(null)
      const [title, setTitle] = useState("")
      const [env, setEnv] = useState("")
      const [busy, setBusy] = useState(false)
      const [copied, setCopied] = useState(false)

      useEffect(() => {
        let dead = false
        setBreach(null)
        api.generate(style, length, words, symbols).then(r => {
          if (dead) return
          setRes(r)
          if (r?.value) api.strength(r.value, []).then(setBreach).catch(() => {})
        }).catch(() => {})
        return () => { dead = true }
      }, [style, length, words, symbols])

      async function store() {
        if (!title.trim()) return
        setBusy(true)
        const field = style === "totp" ? "totp" : style === "token" ? "apiKey" : "password"
        const kind = style === "totp" ? "totp" : style === "token" ? "api-key" : "login"
        try {
          await api.add(title.trim(), kind, "normal", env || "", "", ["generated"], { [field]: res.value }, "")
          onStored(); onClose()
        } catch { } finally { setBusy(false) }
      }

      return jsx(Modal, { open: true, onClose, title: t("generator"), children:
        jsxs("div", { className: "vx-panel", children: [
          jsxs("div", { className: "vx-row", children: [
            jsxs("label", { className: "vx-row vx-muted", children: [t("genStyle"), " ",
              jsx("select", { value: style, onChange: e => setStyle(e.target.value), children: GEN_STYLES.map(k => jsx("option", { value: k, children: t("genStyles." + k) }, k)) })] }),
            style === "password" && jsxs("label", { className: "vx-row vx-muted", children: [t("genLength"), " ", jsx("input", { type: "range", min: 12, max: 64, value: length, onInput: e => setLength(+e.target.value) }), " ", length] }),
            style === "passphrase" && jsxs("label", { className: "vx-row vx-muted", children: [t("genWords"), " ", jsx("input", { type: "range", min: 3, max: 8, value: words, onInput: e => setWords(+e.target.value) }), " ", words] }),
            style === "password" && jsxs("label", { className: "vx-row vx-muted", children: [jsx("input", { type: "checkbox", checked: symbols, onChange: e => setSymbols(e.target.checked) }), " ", t("genSymbols")] }),
          ] }),
          res?.value && jsxs("div", { className: "vx-row", children: [
            jsx("code", { className: "vx-mask", children: res.value }),
            jsx(Button, { size: "sm", variant: "ghost", onClick: async () => { await navigator.clipboard.writeText(res.value); setCopied(true) }, children: copied ? "✓" : t("copy") }),
            jsx(StrengthBar, { score: Math.min(4, Math.floor((res.strengthBits ?? 0) / 20)), bits: res.strengthBits }),
          ] }),
          breach && jsxs("span", { className: "vx-row", children: [
            breach.breached
              ? jsx("span", { className: "vx-danger-note", children: t("breached") })
              : jsx("span", { className: "vx-muted", children: breach.breachSource === "offline" ? t("breachOffline") : t("breachOk") }),
          ] }),
          jsxs("div", { className: "vx-row", children: [
            jsx(Input, { className: "vx-input", placeholder: "title", value: title, onChange: e => setTitle(e.target.value) }),
            (style === "token" || style === "password") && jsx(Input, { style: { width: 180 }, placeholder: "DSH_VAR", value: env, onChange: e => setEnv(e.target.value.toUpperCase()) }),
            jsx(Button, { variant: "primary", disabled: busy || !title.trim() || !res?.value, onClick: store, children: t("store") }),
          ] }),
          jsxs("div", { className: "vx-actions", children: [
            jsx(Button, { variant: "ghost", onClick: onClose, children: t("close") }),
          ] }),
        ] }) })
    }

    // Policy card — radio for access mode, toggles for flags.
    function PolicyCard({ t, api, policy, setPolicy, busy }) {
      const order = ["sealed", "readonly", "write", "edit"]
      return jsxs("div", { className: "vx-card", children: [
        jsxs("h3", { children: [jsx(StateDot, { status: policy.accessMode === "sealed" ? "offline" : "online" }), t("policy"),
          jsx("span", { className: "vx-badge", children: t("modes." + policy.accessMode) })] }),
        jsx("div", { className: "vx-muted", style: { marginBottom: 10 }, children: t("policyHint") }),
        jsx("div", { className: "vx-grid", children: order.map(m => jsx("label", {
          className: "vx-radio" + (policy.accessMode === m ? " sel" : ""),
          onClick: () => { if (policy.accessMode !== m) setPolicy({ accessMode: m }) },
          children: jsxs(Fragment, { children: [
            jsx("input", { type: "radio", checked: policy.accessMode === m, onChange: () => setPolicy({ accessMode: m }), disabled: busy }),
            jsxs("div", { children: [jsx("b", { children: t("modes." + m) }),
              m === "edit" && jsx("div", { className: "vx-danger-note", children: "⚠ " + t("deleteEntry") }),
              m === "sealed" && jsx("div", { className: "vx-muted", children: "0 tools" }),
            ] }),
          ] }),
        }, m)) }),
        jsxs("div", { className: "vx-row", style: { marginTop: 10 }, children: [
          jsxs("label", { className: "vx-row vx-muted", title: t("autoCaptureHint"), children: [jsx("input", { type: "checkbox", checked: !!policy.autoCapture, onChange: e => setPolicy({ autoCapture: e.target.checked }) }), " ", t("autoCapture")] }),
          jsxs("label", { className: "vx-row vx-muted", title: t("totpViaHint"), children: [jsx("input", { type: "checkbox", checked: !!policy.totpViaModel, onChange: e => setPolicy({ totpViaModel: e.target.checked }) }), " ", t("totpVia")] }),
          jsxs("label", { className: "vx-row vx-muted", title: t("envExportHint"), children: [jsx("input", { type: "checkbox", checked: !!policy.envExport, onChange: e => setPolicy({ envExport: e.target.checked }) }), " ", t("envExport")] }),
        ] }),
      ] })
    }

    // Hash-chained audit trail with verify button.
    function AuditCard({ t, api }) {
      const [rows, setRows] = useState(null)
      const [check, setCheck] = useState(null)
      return jsxs("div", { className: "vx-card", children: [
        jsxs("h3", { children: [
          jsx("span", { className: "vx-badge", children: t("audit") }),
          jsx(Button, { size: "sm", variant: "ghost", onClick: async () => setRows(await api.recentAudit(40)), children: t("load") }),
          jsx(Button, { size: "sm", variant: "ghost", onClick: async () => setCheck(await api.verifyAudit()), children: t("auditVerify") }),
          check && jsx("span", { className: check.valid ? "vx-muted vxbadge-ok" : "vx-danger-note", children: check.valid ? t("auditOk").replace("{n}", check.count) : t("auditBroken").replace("{n}", check.brokenAt + 1) }),
        ] }),
        rows && rows.length > 0 && jsx("div", { className: "vx-audit", children: jsxs("table", { children: [
          jsxs("thead", { children: jsx("tr", { children: [t("at"), t("actor"), t("action"), t("detail")].map(h => jsx("th", { children: h }, h)) }) }),
          jsx("tbody", { children: rows.map((r, i) => jsxs("tr", { children: [
            jsx("td", { children: new Date(r.at).toLocaleString() }),
            jsx("td", { children: r.actor }),
            jsxs("td", { children: [r.action, r.ok === false && jsx("span", { className: "vx-danger-note", children: " ✗" })] }),
            jsx("td", { className: "d", children: [r.title ?? r.entryId ?? "", r.detail ? " · " + r.detail : ""].join("") }),
          ] }, i)) }),
        ] }) }),
      ] })
    }

    // Backup / rotation / integrity.
    function BackupCard({ t, api, snapshot, reload }) {
      const [pw, setPw] = useState("")
      const [doc, setDoc] = useState(null)
      const [file, setFile] = useState(null)
      const [importPw, setImportPw] = useState("")
      const [msg, setMsg] = useState(null)
      const [rot, setRot] = useState(null)
      const canMutate = snapshot && snapshot.exists && !snapshot.locked

      function flash(ok, text) { setMsg({ ok, text }) }

      return jsxs("div", { className: "vx-card", children: [
        jsxs("h3", { children: [jsx("span", { className: "vx-badge", children: t("backup") }),
          canMutate && jsx(Button, { size: "sm", variant: "ghost", onClick: async () => {
            const r = await api.verifyVault()
            flash(r.ok, r.ok ? t("verifyVaultOk").replace("{n}", r.total) : t("verifyVaultFail").replace("{n}", r.broken.length))
          }, children: t("verifyVault") })] }),
        jsxs("div", { className: "vx-row", children: [
          jsx(Input, { type: "password", placeholder: t("exportTarget"), value: pw, onChange: e => setPw(e.target.value), style: { maxWidth: 260 } }),
          jsx(Button, { size: "sm", variant: "outline", disabled: !canMutate || pw.length < 10, onClick: async () => {
            const r = await api.exportVault(pw)
            if (r.ok) { setDoc(r.doc); flash(true, "") } else flash(false, r.error ?? t("err"))
          }, children: t("export") }),
          doc && jsx(Button, { size: "sm", variant: "primary", onClick: () => {
            const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" }))
            const a = document.createElement("a"); a.href = url; a.download = "vaultx-export.json"; a.click()
            URL.revokeObjectURL(url)
          }, children: t("download") }),
        ] }),
        jsx("div", { className: "vx-muted", children: t("exportHint") }),
        jsxs("div", { className: "vx-row", children: [
          jsx("input", { type: "file", accept: ".json", onChange: e => setFile(e.target.files[0] ?? null) }),
          jsx(Input, { type: "password", placeholder: t("password"), value: importPw, onChange: e => setImportPw(e.target.value), style: { maxWidth: 200 } }),
          jsx(Button, { size: "sm", variant: "outline", disabled: !file || importPw.length < 10, onClick: async () => {
            if (!window.confirm(t("importConfirm"))) return
            try { const r = await api.importVault(JSON.parse(await file.text()), importPw); if (r.ok) { reload(); flash(true, `imported ${r.entries}`) } else flash(false, r.error ?? t("err")) }
            catch (e) { flash(false, String(e?.message ?? e)) }
          }, children: t("import") }),
        ] }),
        rot
          ? jsxs("div", { className: "vx-row", children: [
            jsx(Input, { type: "password", placeholder: t("rotateOld"), value: rot.oldPassword ?? "", onChange: e => setRot(r => ({ ...r, oldPassword: e.target.value })) }),
            jsx(Input, { type: "password", placeholder: t("rotateNew"), value: rot.newPassword ?? "", onChange: e => setRot(r => ({ ...r, newPassword: e.target.value })) }),
            jsx(Button, { size: "sm", variant: "primary", disabled: !(rot.oldPassword && rot.newPassword && rot.newPassword.length >= 10), onClick: async () => {
              const r = await api.rotate(rot.oldPassword, rot.newPassword)
              if (r.ok) { setRot(null); flash(true, t("doneRotate")) } else flash(false, r.error ?? t("err"))
            }, children: t("save") }),
            jsx(Button, { size: "sm", variant: "ghost", onClick: () => setRot(null), children: t("cancel") }),
          ] })
          : jsx(Button, { size: "sm", variant: "ghost", disabled: !canMutate, onClick: () => setRot({}), children: t("rotate") }),
        msg && msg.text && jsx("div", { className: msg.ok ? "vx-muted vxbadge-ok" : "vx-danger-note", children: msg.text }),
      ] })
    }

    // Create / unlock hero panels.
    function InitPanel({ t, api, mode, snapshot, onDone }) {
      const [pw, setPw] = useState("")
      const [pw2, setPw2] = useState("")
      const [err, setErr] = useState("")
      const [busy, setBusy] = useState(false)
      const isCreate = mode === "create"
      async function go() {
        if (isCreate && pw.length < 10) { setErr(t("masterTooShort") ?? ""); return }
        if (isCreate && pw !== pw2) { setErr(t("mismatch")); return }
        setErr(""); setBusy(true)
        try {
          const r = isCreate ? await api.create(pw) : await api.unlock(pw)
          if (r && r.ok === false) setErr(r.error ?? t("err"))
          else onDone()
        } catch (e) { setErr(String(e?.message ?? e)) } finally { setBusy(false) }
      }
      return jsxs("div", { className: "vx-card", children: [
        jsx(LockHero, {}),
        jsxs("h3", { style: { justifyContent: "center" }, children: [isCreate ? t("createTitle") : t("lockedTitle")] }),
        jsx("div", { className: "vx-muted", style: { textAlign: "center", marginBottom: 12 }, children: isCreate ? t("createHint") : t("lockedHint") }),
        jsxs("div", { className: "vx-row", children: [
          jsx(Input, { type: "password", placeholder: t("password"), value: pw, onChange: e => setPw(e.target.value), onKeyDown: e => e.key === "Enter" && go() }),
          isCreate && jsx(Input, { type: "password", placeholder: t("confirmPassword"), value: pw2, onChange: e => setPw2(e.target.value), onKeyDown: e => e.key === "Enter" && go() }),
          jsx(Button, { variant: "primary", disabled: busy || !pw, onClick: go, children: isCreate ? t("create") : t("unlock") }),
        ] }),
        err && jsx("div", { className: "vx-danger-note", children: err }),
        snapshot?.lockoutSeconds > 0 && jsx("div", { className: "vx-danger-note", children: t("lockout").replace("{n}", snapshot.lockoutSeconds) }),
        jsx("div", { className: "vx-seal", style: { textAlign: "center", marginTop: 10 }, children: t("seal") }),
      ] })
    }

    // ─────────────────────────────────────────────────────────────────────
    // The section root
    // ─────────────────────────────────────────────────────────────────────
    function VaultXSection({ t, api, snapshot, setSnapshot, reload, renderSlot }) {
      const [entries, setEntries] = useState([])
      const [query, setQuery] = useState("")
      const [editor, setEditor] = useState(null)   // undefined | {mode:'add'} | entry
      const [genOpen, setGenOpen] = useState(false)
      const [toast, setToast] = useState(null)
      const [busy, setBusy] = useState(false)
      const policy = snapshot?.policy ?? { accessMode: "readonly" }

      useEffect(() => { if (toast) { const id = setTimeout(() => setToast(null), 2600); return () => clearTimeout(id) } }, [toast])

      // Load list + policy whenever we become unlocked.
      useEffect(() => {
        if (snapshot?.exists && !snapshot?.locked) {
          api.list().then(setEntries).catch(() => {})
          api.getPolicy().then(p => setSnapshot(s => ({ ...s, policy: p }))).catch(() => {})
        } else setEntries([])
      }, [snapshot?.locked, snapshot?.exists])

      async function refresh() {
        try { setSnapshot(await api.status()) } catch { }
      }
      async function doSetPolicy(patch) {
        setBusy(true)
        try {
          const next = await api.setPolicy(patch.accessMode ?? null, typeof patch.autoCapture === "boolean" ? patch.autoCapture : null, typeof patch.totpViaModel === "boolean" ? patch.totpViaModel : null, typeof patch.envExport === "boolean" ? patch.envExport : null)
          setSnapshot(s => ({ ...s, policy: next }))
          setToast(t("save") + " ✓")
        } catch (e) { setToast(String(e?.message ?? e)) } finally { setBusy(false) }
      }

      async function del(entry) {
        if (!window.confirm(t("deleteConfirm").replace("{title}", entry.title))) return
        setBusy(true)
        try { await api.remove(entry.id); refresh(); setToast("🗑 " + entry.title) } catch { } finally { setBusy(false) }
      }

      if (!snapshot) return null
      if (!snapshot.exists) return jsxs("div", { className: "vx-panel", children: [
        jsx(InitPanel, { t, api, mode: "create", snapshot, onDone: refresh }),
        jsx(BackupCard, { t, api, snapshot, reload: refresh }),
      ] })
      if (snapshot.locked) return jsxs("div", { className: "vx-panel", children: [
        jsx(InitPanel, { t, api, mode: "unlock", snapshot, onDone: refresh }),
      ] })

      const filtered = useMemo(() => {
        const q = query.toLowerCase().trim()
        return !q ? entries : entries.filter(e => [e.title, ...(e.tags ?? []), e.env ?? "", e.kind].join(" ").toLowerCase().includes(q))
      }, [entries, query])

      return jsxs("div", { className: "vx-panel", children: [
        jsxs("div", { className: "vx-card", children: [
          jsxs("h3", { children: [
            jsx(StateDot, { status: "online" }), t("nav"),
            jsxs("span", { className: "vx-badge", children: [t("status.entries"), " ", snapshot.entries] }),
            jsxs("span", { className: "vx-badge", children: [t("status.mode"), ": ", t("modes." + policy.accessMode)] }),
            (snapshot.envVariables?.length ?? 0) > 0 && jsxs("span", { className: "vx-badge", children: [t("envVarsChip"), " ", snapshot.envVariables.length] }),
          ] }),
          jsxs("div", { className: "vx-row", children: [
            jsx(Input, { placeholder: t("searchPlaceholder"), value: query, onChange: e => setQuery(e.target.value), style: { maxWidth: 280 } }),
            jsx(Button, { variant: "primary", size: "sm", onClick: () => setEditor({ mode: "add" }), children: t("addEntry") }),
            jsx(Button, { variant: "outline", size: "sm", onClick: () => setGenOpen(true), children: t("generator") }),
            jsx(Button, { variant: "ghost", size: "sm", onClick: async () => { await api.lock(); refresh() }, children: t("lock") }),
          ] }),
        ] }),

        entries.length === 0
          ? jsxs("div", { className: "vx-empty", children: [jsx(LockHero, {}), jsx("div", { className: "vx-muted", children: t("empty") })] })
          : jsx("div", { className: "vx-grid", children: filtered.map(e => jsxs("div", { className: "vx-entry", children: [
            jsxs("div", { className: "vx-entry-title", children: [
              e.title,
              jsx("span", { className: "vx-badge " + e.sensitivity, children: t("sens." + e.sensitivity) }),
              (e.tags ?? []).includes("model") && jsx("span", { className: "vx-badge model", children: t("modelOrigin") }),
            ] }),
            jsxs("div", { className: "vx-row", children: [
              jsx("span", { className: "vx-muted", children: t("kinds." + e.kind) }),
              e.env && jsx("span", { className: "vx-env", children: "$" + e.env }),
            ] }),
            jsx("div", { className: "vx-fields", children: (e.fields ?? []).filter(f => f !== "__notes__").map(f => jsx(FieldLine, { t, api, entryId: e.id, name: f }, f)) }),
            jsxs("div", { className: "vx-row", children: [
              (e.fields ?? []).includes("totp") && jsx(TotpChip, { t, api, entryId: e.id }),
              jsx("span", { style: { flex: 1 } }),
              jsx(Button, { size: "sm", variant: "ghost", onClick: () => setEditor(e), children: "✎" }),
              jsx(Button, { size: "sm", variant: "ghost", onClick: () => del(e), children: "🗑" }),
            ] }),
          ] }, e.id)) }),

        jsx(PolicyCard, { t, api, policy, setPolicy: doSetPolicy, busy }),
        jsx(AuditCard, { t, api }),
        jsx(BackupCard, { t, api, snapshot, reload: refresh }),

        editor && jsx(EntryEditor, { t, api, entry: editor.mode ? undefined : editor, onClose: () => setEditor(null), onSaved: () => { setEditor(null); refresh() } }),
        genOpen && jsx(Generator, { t, api, onClose: () => setGenOpen(false), onStored: refresh }),
        toast !== null && jsx(Toast, { text: toast, onDone: () => setToast(null) }),
      ] })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Registration
    // ─────────────────────────────────────────────────────────────────────
    const inject = ["slots", "locale", "connection"]

    function apply(ctx) {
      injectStyles()
      ctx.effect(() => ctx.locale.register(NS, { zh: flat(zh), en: flat(en) }), "dsh-vaultx: dictionaries")
      const t = ctx.locale.bind(NS)
      const connection = ctx.get("connection")

      // Typert envelope: rpc to `/api` namespace `vaultx/<method>` with named
      // args matching the HOST METHOD parameter names exactly.
      async function call(method, args = {}) {
        const result = await connection.rpc.call("/api", `vaultx/${method}`, { args })
        if (!result.ok) throw new Error(String(result.error?.message ?? result.error ?? `${method} failed`))
        return result.value
      }

      const api = {
        status: () => call("status", {}),
        unlock: (password) => call("unlock", { password }),
        create: (password) => call("create", { password }),
        lock: () => call("lock", {}),
        list: () => call("list", {}),
        reveal: (id, field) => call("reveal", { id, field }),
        masked: (id, field) => call("masked", { id, field }),
        add: (title, kind, sensitivity, env, envField, tags, fields, notes) => call("add", { title, kind, sensitivity, env, envField, tags, fields, notes }),
        update: (id, patch) => call("update", { id, patch }),
        remove: (id) => call("remove", { id }),
        generate: (style, length, words, symbols) => call("generate", { style, length, words, symbols }),
        strength: (value, personal) => call("strength", { value, personal }),
        totpCode: (id) => call("totpCode", { id }),
        rotate: (oldPassword, newPassword) => call("rotate", { oldPassword, newPassword }),
        exportVault: (targetPassword) => call("exportVault", { targetPassword }),
        importVault: (doc, password) => call("importVault", { doc, password }),
        getPolicy: () => call("getPolicy", {}),
        setPolicy: (accessMode, autoCapture, totpViaModel, envExport) => call("setPolicy", { accessMode, autoCapture, totpViaModel, envExport }),
        recentAudit: (limit) => call("recentAudit", { limit }),
        verifyAudit: () => call("verifyAudit", {}),
        verifyVault: () => call("verifyVault", {}),
      }

      function Root() {
        const [snapshot, setSnapshot] = useState(null)
        useEffect(() => {
          let dead = false
          const load = () => api.status().then(st => { if (!dead) setSnapshot(st) }).catch(() => {})
          load()
          const id = setInterval(load, 25000)
          return () => { dead = true; clearInterval(id) }
        }, [])
        return jsx(VaultXSection, { t, api, snapshot, setSnapshot })
      }

      ctx.slots.inject("settings.section", () => ctx.slots.register({
        name: "settings.section",
        id: "vaultx",
        order: 31,
        label: () => t("nav"),
        locale: NS,
        inject: () => ({}),
      }, Root))
    }

    exports.NS = NS
    exports.apply = apply
    exports.inject = inject
    exports.VaultXSection = VaultXSection
    exports.injectStyles = injectStyles
    return module.exports
  },
})
