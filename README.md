# pi-safety-gate

pi 扩展：在 `tool_call` 上拦截危险 bash 命令与受保护路径写入。

它不是沙箱。pi 官方文档的措辞是 `it does not ask for approval before every tool call`，真正的
边界靠容器、VM 或独立用户。这个扩展只做一件事：把不可逆的手滑变成一次确认，并把确认次数
压到可以常开。

---

## 分级

| 级别 | 判定 | 行为 |
|---|---|---|
| `critical` | 出 cwd、≥2 个目标、通配符、系统级目录、单目标 ≥20 项 | 列目标清单 + 两次确认（终端或 Kindle 任一通道） |
| `dangerous` | 语义明确的破坏：强推、`reset --hard`、提权、写裸设备、脚本落地再执行、管道进 shell、内联破坏性代码 | 一次确认；能改写成移入废纸篓则不打扰 |
| `notice` | 只是无法核验（引号不闭合） | 只通知，不拦 |
| `protected-path` | `write`/`edit` 写受保护路径 | 直接阻断，无确认框 |

---

## 压低打扰的三种机制

都不降低默认强度。

### 删除改写成移入废纸篓

`rm -rf dist` 这类单条、目标全在 cwd 内、无通配符的删除会被改写成：

```sh
mkdir -p '~/.pi/eink/trash/<timestamp>' && mv -- dist '~/.pi/eink/trash/<timestamp>/'
```

删除因此可恢复，不再询问，只发一条通知。出 cwd、多命令、带通配符、路径含空格的删除不改写，
仍然确认。只要有一段 `rm` 不能安全改写，整条命令都不改写，否则未改写的那段会跟着改写后的
命令一起被静默放行。

### 离开前预授权

`~/.pi/eink/gate-policy.json`：

```json
{
  "allowUntil": "2026-11-02T09:00:00Z",
  "allow": [
    { "commandRe": "^npm (run )?(test|lint|build)\\b" },
    { "commandRe": "^git push origin main$" }
  ]
}
```

- 只对 `dangerous` 生效；`critical` 与受保护路径永不自动放行
- `allowUntil` 过期后整个文件失效，忘了撤也不会永久敞开
- 每次放行写一行到 `~/.pi/eink/gate.log`，回来可逐条核对
- 文件缺失或 JSON 损坏等同于不存在，不静默放行

### 无人应答不再挂死

终端对话框默认等 90s（`EINK_GATE_TIMEOUT_MS` 可调），超时按拒绝处理并通知：这一条命令失败，
会话继续，而不是整个 TUI 卡在确认框上。Kindle 通道本身有 120s 超时。

---

## 受保护内容

目录名命中 `node_modules`、`.git`、`.ssh`、`.aws`、`.gnupg`；绝对前缀命中 `~/.pi/agent/**`
（本扩展自己的源码、`settings.json`、`auth.json`、其它扩展）与 `~/.pi/eink/**`（`token`、
`pin`、`allow_ips`）；文件形状命中 `.env`（模板后缀除外）、私钥与证书。

bash 写入受保护路径走确认流，`write`/`edit` 工具直接阻断。

凭据连确认都不给：`~/.pi/eink/{token,pin,masked_secrets}` 与 `~/.pi/agent/auth.json` 被 `rm`、
`truncate` 或重定向写入时直接阻断，不弹确认框。agent 没有任何正当理由去动它们，需要轮换请
人工操作。

### 零确认

| 路径 | 为什么安全 |
|---|---|
| `~/.pi/eink/trash/**` | 废纸篓本身就是已删内容的暂存区 |
| `~/.pi/eink/*.log`、`*.log.1` | 纯诊断信息 |
| `~/Library/Caches/**`、`~/.cache/**` | 用户级缓存，重建即得 |
| `**/node_modules/.cache/**`、`__pycache__`、`.pytest_cache`、`.mypy_cache`、`.ruff_cache`、`.turbo`、`.parcel-cache`、`.svelte-kit`、`.next/cache` | 构建与测试缓存 |
| `find <上述目录> -delete` | 同一类目标，换了写法 |

刻意不收 `dist`、`build`、`.next` 这类名字，项目里可能有同名源码目录。它们走移入废纸篓，
同样零确认但可恢复。`node_modules` 本身仍受保护，它与 `.git`、`.ssh` 同级敏感。

`npm cache clean`、`pnpm store prune`、`yarn cache clean`、`brew cleanup` 不触发任何规则。

`rm -rf ~/.pi/eink/*` 依然要确认，因为里面有 `token`；`~/.pi/eink/trash/../token` 这类绕法会被
`normalize` 拆穿。

两项自动维护：会话启动时清掉超过 14 天的废纸篓批次（`TRASH_MAX_AGE_MS`）；
`gate.log` 超过 1 MB 轮转成 `gate.log.1`，只保留一代。

---

## 安装

```sh
git clone https://github.com/snowspruce/pi-safety-gate
ln -sfn "$PWD/pi-safety-gate/extensions/safety-gate" ~/.pi/agent/extensions/safety-gate
```

也可以作为 pi package 安装：`pi install ~/pi-safety-gate`。两者不要并存，否则同一命令会问两次。

用符号链接而不是 package，是因为扩展在频繁迭代：松散或软链扩展会在 `/reload` 时重新读取；
新增的 package 不会被已运行会话的 `/reload` 纳入，`pi list` 也看不到软链。稳定后再换成
package。

pi-eink 的 Kindle 远程确认依赖本扩展的 `pending.json` 握手。不装它也能用 pi-eink，只是危险
命令只能在本机终端确认。

---

## 已知边界

1. 执行一个已经存在的脚本（`sh ./x.sh`），脚本内容不在命令文本里
2. 项目脚本内部做什么（`npm run xxx`、`make`）
3. 数据外传（`curl --data @file`）
4. 任何针对命令文本的混淆：分片拼接、多层编码
5. pi 以 `-p` 或 `--mode json` 运行时没有 UI，一律阻断（fail-closed）

---

## 配置

| 变量 | 默认 | 含义 |
|---|---|---|
| `EINK_GATE_TIMEOUT_MS` | `90000` | 终端确认等待时长，超时按拒绝 |
| `EINK_BRIDGE_PORT` | — | 由 eink-bridge 使用，与本扩展共享 `bridges.json` 判断本进程是否有 bridge |

---

## 测试与规则调优

见 [DEVELOPMENT.md](DEVELOPMENT.md)。
