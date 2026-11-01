# safety-gate

pi 扩展：在 `tool_call` 上拦危险 bash 命令与受保护路径写入。

**它不是沙箱。** pi 官方文档说得很直白：`it does not ask for approval before every tool call`，
真正的边界靠容器 / VM / 独立用户。这个扩展是把「不可逆的手滑」变成一次确认的**人类在环护栏**，
并尽量让确认次数少到可以常开。

## 分级

| 级别 | 判定 | 行为 |
|---|---|---|
| `critical` | 出 cwd、≥2 个目标、通配符、系统级目录、单个目标 ≥20 项 | 列目标清单 + **两次**确认（终端 / Kindle 任一通道） |
| `dangerous` | 语义明确的破坏（强推、`reset --hard`、提权、写裸设备、脚本落地再执行、管道进 shell、内联破坏性代码） | 一次确认；若能改写成「移入废纸篓」则不打扰 |
| `notice` | 只是无法核验（引号不闭合） | 只通知，不拦 |
| `protected-path` | `write`/`edit` 写受保护路径 | **直接阻断**，无确认框 |

## 三种「少打扰」机制（都不降低默认强度）

### 1. 删除改写成移入废纸篓

`rm -rf dist` 这类**单条、目标全在 cwd 内、无通配符**的删除会被改写成：

```sh
mkdir -p '~/.pi/eink/trash/<timestamp>' && mv -- dist '~/.pi/eink/trash/<timestamp>/'
```

于是删除可恢复，因此不再询问，只发一条通知。出 cwd、多命令、带通配符、路径含空格的删除**不改写**，仍然确认。

**清理废纸篓本身不拦**：`rm -rf ~/.pi/eink/trash` / `~/.pi/eink/trash/*` / 某个批次目录都是零确认——那是它的设计用途。
但 `~/.pi/eink/trash/../token` 这类绕法会被 `normalize` 拆穿，仍按受保护路径处理；混合目标（废纸篓 + 真实路径）仍按真实路径升级。

### 2. 离开前预授权（`~/.pi/eink/gate-policy.json`）

```json
{
  "allowUntil": "2026-11-02T09:00:00Z",
  "allow": [
    { "commandRe": "^npm (run )?(test|lint|build)\\b" },
    { "commandRe": "^git push origin main$" }
  ]
}
```

- 只对 `dangerous` 生效；**`critical` 与受保护路径永不自动放行**
- `allowUntil` 过期后整个文件失效（忘了撤也不会永久敞开）
- 每次放行都写一行到 `~/.pi/eink/gate.log`，回来可逐条核对
- 文件缺失或 JSON 坏了 → 等同于不存在（不静默放行）

### 3. 无人应答不再挂死

终端对话框默认等 **90s**（`EINK_GATE_TIMEOUT_MS` 可调）。超时按「拒绝」处理并通知：
这一条命令失败，会话继续，而不是整个 TUI 卡在确认框上。Kindle 通道本身有 120s 超时。

## 误报调优（基于真实命令语料）

用本机历史会话里 **2132 条去重 bash 命令**跑过规则，逐步压掉误报：

| 问题 | 处理 |
|---|---|
| `curl … \| python3 -c '…'` 被当成执行远程代码（67 条） | 只有管道进 **shell**、或进解释器但**没有** `-c/-e`（即从 stdin 读脚本）才算 |
| `cd /tmp && rm -rf /tmp/x` 的目标被判成"cwd 外"（20 条） | 逐段跟踪 `cd`，用它算后续段的 cwd |
| `CH=…; "$CH"` 报"命令名是变量"（40 条） | 同一条命令里能解析出**字面量**赋值就代入再判；带 `$`/反引号的不算 |
| `> $TMP/…`（`TMP=$(mktemp -d)`）报"写入是变量"（29 条） | `mktemp` 变量的写入直接放过（路径必然在临时目录） |
| `cat > x.py <<'EOF' … EOF; python3 x.py` 全被拦（21 条） | heredoc 写的脚本内容**就在命令文本里**：递归分析正文，只有正文真有问题才拦 |
| `/tmp` 下的删除被判 critical（16 条） | `/tmp`、`$TMPDIR`、`/private/tmp` 视为一次性内容，不再升级 |
| `sed -i 's|a|b|' <受保护路径>` 被当成写一个叫 `s\|a\|b\|` 的路径 | 原地编辑类命令跳过第一个位置参数（它是脚本，不是路径） |
| `git push --force --dry-run` 与真强制推送一样对待 | `--dry-run` / `-n` 明确不写远端，不再拦 |

后续又压掉了三类解析噪音：

| 问题 | 处理 |
|---|---|
| heredoc 正文被当成命令逐行解析（写 `.py`/`.sh` 时成片误报） | 先把正文挖掉；`<<` 的结束标记必须行首精确匹配，`<<-` 才允许前导 tab |
| `sed -i '' 's/x/y/' f`（macOS 空备份后缀）把脚本当路径 | 先剔除空串再取第 2 个位置参数 |
| `D="$HOME/…"; cp "$D/a" "$D/b"` 报"写入是变量" | 同一条命令内解析字面量赋值（`$HOME` 也展开），支持 `$VAR/后缀` 前缀展开 |

结果（同一语料 2132 条）：静默放行 **93.4%**，改写为移走 28 条，仍然询问 **4.9%**；
剔掉我自己写的门禁测试命令后，**真实工作命令 1664 条里只有 54 条（3.2%）会询问**。

剩下会问的，基本都是真该问的：`sudo`、`git reset --hard`、写 `~/.pi/eink/*` 这类本机状态、
出 cwd 的删除、以及少数"无法核验"的变量命令。

改写有一条硬约束：**只要有一段 `rm` 不能安全改写（通配符、cwd 外、变量），整条命令就不改写**——
否则没改写的那段会跟着改写后的命令一起被静默放行。

## 可以直接删的东西（零确认）

| 路径 | 为什么安全 |
|---|---|
| `~/.pi/eink/trash/**` | 废纸篓本身就是已删内容的暂存区 |
| `~/.pi/eink/*.log`、`*.log.1` | 纯诊断信息，丢了不影响任何功能 |
| `~/Library/Caches/**`、`~/.cache/**` | 用户级缓存，重建即得 |
| `**/node_modules/.cache/**`、`__pycache__`、`.pytest_cache`、`.mypy_cache`、`.ruff_cache`、`.turbo`、`.parcel-cache`、`.svelte-kit`、`.next/cache` | 纯构建/测试缓存，删了会自己长回来 |
| `find <上述目录> -delete` | 与上面同一类目标，只是换了写法 |

刻意**不**收 `dist` / `build` / `.next` 这种名字：项目里可能有同名的源码目录。它们走"移入废纸篓"，
同样零确认但可恢复。`node_modules` 本身仍受保护（它 `.git`、`.ssh` 同级敏感）。

`npm cache clean`、`pnpm store prune`、`yarn cache clean`、`brew cleanup` 本来就不触发任何规则（不需要白名单）。

`rm -rf ~/.pi/eink/*` 依然要确认（里面有 `token`）；`~/.pi/eink/trash/../token` 这类绕法会被 `normalize` 拆穿。

### 两个自动维护（不需要人管）

- **废纸篓**：会话启动时清掉超过 **14 天**的批次（`TRASH_MAX_AGE_MS`），不会无限涨
- **`gate.log`**：超过 **1 MB** 轮转成 `gate.log.1`，只保留一代

## 凭据：连确认都不给（hard block）

`~/.pi/eink/{token,pin,masked_secrets}`、`~/.pi/agent/auth.json` 被 `rm`、`truncate`、重定向写入时
**直接阻断**，不弹确认框——agent 没有任何正当理由去动它们，需要轮换请人工操作。

## 受保护的内容

- 目录名命中：`node_modules`、`.git`、`.ssh`、`.aws`、`.gnupg`
- 绝对前缀：`~/.pi/agent/**`（本扩展自己的源码、`settings.json`、`auth.json`、其它扩展）、`~/.pi/eink/**`（`token`、`pin`、`allow_ips`）
- 文件形状：`.env`（模板后缀除外）、私钥 / 证书
- bash 写入受保护路径走确认流；`write`/`edit` 工具直接阻断

## 已知边界（改不掉，别指望它）

1. 执行一个**已经存在**的脚本（`sh ./x.sh`）——脚本内容不在命令文本里
2. 项目脚本（`npm run xxx`、`make`）内部做什么
3. 数据外传（`curl --data @file`）
4. 任何针对命令文本的混淆（分片拼接、多层编码）
5. 若 pi 以 `-p` / `--mode json` 运行，没有 UI，一律阻断（fail-closed）

## 测试

```sh
npm test          # = node --experimental-strip-types extensions/safety-gate/rules.test.ts
```

规则引擎（`rules.ts`）刻意不 import `pi`，所以能在 agent 之外直接跑。
`index.ts` 依赖运行时注入的 `ExtensionContext`，只能靠真实 pi 会话或 harness 验证。

## 安装

```sh
git clone https://github.com/snowspruce/pi-safety-gate
ln -sfn "$PWD/pi-safety-gate/extensions/safety-gate" ~/.pi/agent/extensions/safety-gate
```

（或者作为 pi package：`pi install ~/pi-safety-gate` —— 两者**不要并存**，否则同一命令会问两次。）

`pi-eink` 的 Kindle 远程确认依赖本扩展的 `pending.json` 握手；不装它也能用 pi-eink，
只是危险命令只能在本机终端确认，Kindle 上没有允许/拒绝按钮。

## 本机现状（开发期的加载方式）

```sh
ln -sfn ~/Documents/Program/pi-safety-gate/extensions/safety-gate \
        ~/.pi/agent/extensions/safety-gate
```

用**符号链接**而不是 pi package，因为这个扩展在频繁迭代：

- 松散/软链扩展会在 `/reload` 时重新读取，改完 `rules.ts` 直接 reload 就生效；
- 新增的 **package** 不会被已在运行的会话的 `/reload` 纳入（实测：同一个 session 连续两次 reload 后仍无门禁，而新进程正常）。
- 代价：`pi list` 里看不到它（那命令只列 packages）。

等它稳定了再换成 package（`pi install ~/Documents/Program/pi-safety-gate` 并删掉软链，**不要两者并存**，否则同一命令会问两次）。

## 配置

| 变量 | 默认 | 含义 |
|---|---|---|
| `EINK_GATE_TIMEOUT_MS` | `90000` | 终端确认等待时长，超时按拒绝 |
| `EINK_BRIDGE_PORT` | — | 由 eink-bridge 使用，与本扩展共享 `bridges.json` 判断「本进程是否有 bridge」 |
