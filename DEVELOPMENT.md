# DEVELOPMENT

维护者笔记。README 只写使用者需要知道的，这里是规则怎么调出来的、怎么验。

## 测试

```sh
npm test          # = node --experimental-strip-types extensions/safety-gate/rules.test.ts
```

规则引擎（`rules.ts`）刻意不 import `pi`，所以能在 agent 之外直接跑。`index.ts` 依赖运行时注入
的 `ExtensionContext`，只能靠真实 pi 会话或 harness 验证。

## 误报调优

用本机历史会话里 2132 条去重 bash 命令跑过规则，逐步压掉误报：

| 问题 | 处理 |
|---|---|
| `curl … \| python3 -c '…'` 被当成执行远程代码（67 条） | 只有管道进 shell、或进解释器但没有 `-c/-e`（即从 stdin 读脚本）才算 |
| `cd /tmp && rm -rf /tmp/x` 的目标被判成 cwd 外（20 条） | 逐段跟踪 `cd`，用它算后续段的 cwd |
| `CH=…; "$CH"` 报命令名是变量（40 条） | 同一条命令里能解析出字面量赋值就代入再判；带 `$` 或反引号的不算 |
| `> $TMP/…`（`TMP=$(mktemp -d)`）报写入是变量（29 条） | `mktemp` 变量的写入直接放过，路径必然在临时目录 |
| `cat > x.py <<'EOF' … EOF; python3 x.py` 全被拦（21 条） | heredoc 写的脚本内容就在命令文本里：递归分析正文，只有正文真有问题才拦 |
| `/tmp` 下的删除被判 critical（16 条） | `/tmp`、`$TMPDIR`、`/private/tmp` 视为一次性内容，不再升级 |
| `sed -i 's\|a\|b\|' <受保护路径>` 被当成写一个叫 `s\|a\|b\|` 的路径 | 原地编辑类命令跳过第一个位置参数，它是脚本不是路径 |
| `git push --force --dry-run` 与真强制推送一样对待 | `--dry-run`、`-n` 明确不写远端，不再拦 |

后续又压掉三类解析噪音：

| 问题 | 处理 |
|---|---|
| heredoc 正文被当成命令逐行解析（写 `.py`/`.sh` 时成片误报） | 先把正文挖掉；`<<` 的结束标记必须行首精确匹配，`<<-` 才允许前导 tab |
| `sed -i '' 's/x/y/' f`（macOS 空备份后缀）把脚本当路径 | 先剔除空串再取第 2 个位置参数 |
| `D="$HOME/…"; cp "$D/a" "$D/b"` 报写入是变量 | 同一条命令内解析字面量赋值（`$HOME` 也展开），支持 `$VAR/后缀` 前缀展开 |

结果（同一语料 2132 条）：静默放行 93.4%，改写为移走 28 条，仍然询问 4.9%。剔掉门禁测试
命令后，真实工作命令 1664 条里只有 54 条（3.2%）会询问。

剩下会问的基本都是真该问的：`sudo`、`git reset --hard`、写 `~/.pi/eink/*` 这类本机状态、
出 cwd 的删除，以及少数无法核验的变量命令。

## 本机加载方式

开发期用符号链接，不用 pi package：

```sh
ln -sfn ~/Documents/Program/pi-safety-gate/extensions/safety-gate \
        ~/.pi/agent/extensions/safety-gate
```

原因：松散或软链扩展会在 `/reload` 时重新读取，改完 `rules.ts` 直接 reload 就生效；新增的
package 不会被已在运行的会话的 `/reload` 纳入（实测同一个 session 连续两次 reload 后仍无
门禁，而新进程正常）。代价是 `pi list` 里看不到它，那条命令只列 packages。

等稳定了再换成 package：`pi install ~/Documents/Program/pi-safety-gate` 并删掉软链。两者不要
并存，否则同一命令会问两次。
