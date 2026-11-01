/**
 * Safety Gate Extension
 *
 * 拦截两类高风险操作，规则实现见 ./rules.ts（纯逻辑，可单测）。
 *   1. 危险 bash 命令 —— rm -rf / 提权 / 强制推送 / 磁盘写入 / 管道执行远程代码 …
 *   2. 敏感路径写入 —— .env / .git/ / node_modules/ / 私钥 / pi 凭据
 *
 * 策略：
 *   - write/edit 命中受保护路径 → 直接阻断（无覆盖入口）
 *   - bash 命中任一规则 → 有 UI 时弹确认，无 UI（-p / --mode json）时一律阻断
 *   - bash 仅因引号不闭合而未命中规则（unparsed）→ 只提示放行，不打断
 *     （rules 对残缺引号内的片段仍逐段检查，所以危险命令不会因此漏掉）
 *
 * pi 本身没有内置沙箱，这是进程内唯一的防线，不是安全边界。
 * 已知边界：无法解析任意脚本内容（`node -e '<代码>'` 检测不到）；
 * 变量间接执行（`R=rm; $R -rf /`）会走「变量命令」分支被拦，但更深的间接无法覆盖。
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { appendFileSync, readdirSync, readFileSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { analyzeCommand, findProtectedPath, planTrashRewrite, type Finding } from "./rules.ts";

const EINK_DIR = join(homedir(), ".pi/eink");
const BRIDGES_FILE = join(EINK_DIR, "bridges.json");
const PENDING_FILE = join(EINK_DIR, "pending.json");
const ANSWER_FILE = join(EINK_DIR, "answer.json");
const REMOTE_TIMEOUT_MS = 120_000;
/**
 * 终端对话框等这么久没人答就按「拒绝」收场。
 * 没有它的话，人不在电脑前时工具调用会永远挂着，整个会话卡死在这一步；
 * 按拒绝处理则只是这一条命令失败，可以把工作留给下一次。
 */
const TERMINAL_TIMEOUT_MS = Number(process.env.EINK_GATE_TIMEOUT_MS ?? 90_000);
/** 删除在这里变成「移动」，留出回头路。 */
const TRASH_ROOT = join(EINK_DIR, "trash");
/** 离开前预授权：见 README / gate.log。 */
const POLICY_FILE = join(EINK_DIR, "gate-policy.json");
/** 每一次自动放行都留痕，回来可以逐条核对。 */
const GATE_LOG = join(EINK_DIR, "gate.log");

function logGate(line: string): void {
	try {
		appendFileSync(GATE_LOG, `${new Date().toISOString()}\tpid=${process.pid}\t${line}\n`);
	} catch {
		// logging must never break the gate
	}
}

/** 废纸篓不能无限涨：超过这些天的批次在会话启动时清掉。 */
const TRASH_MAX_AGE_MS = 14 * 24 * 3600_000;
/** gate.log 超过这个大小就轮转成 gate.log.1，只保留一代。 */
const GATE_LOG_MAX_BYTES = 1_000_000;

function pruneTrash(): void {
	let entries: string[];
	try {
		entries = readdirSync(TRASH_ROOT);
	} catch {
		return; // 还没有废纸篓
	}
	const now = Date.now();
	for (const name of entries) {
		const dir = join(TRASH_ROOT, name);
		try {
			if (now - statSync(dir).mtimeMs > TRASH_MAX_AGE_MS) rmSync(dir, { recursive: true, force: true });
		} catch {
			// 单个批次清理失败不影响其它批次
		}
	}
}

function rotateGateLog(): void {
	try {
		if (statSync(GATE_LOG).size <= GATE_LOG_MAX_BYTES) return;
		renameSync(GATE_LOG, `${GATE_LOG}.1`);
	} catch {
		// 没有日志文件，或轮转失败：宁可不轮转，也不要丢记录
	}
}

function trashDirFor(): string {
	return join(TRASH_ROOT, new Date().toISOString().replace(/[:.]/g, "-"));
}

/**
 * 预授权策略（可选文件 ~/.pi/eink/gate-policy.json）：
 *   { "allowUntil": "2026-11-02T09:00:00Z",
 *     "allow": [{ "commandRe": "^npm (run )?(test|lint|build)\\b" }] }
 * 只对「语义明确的破坏」生效；critical 和受保护路径永不自动放行。
 */
function policyHit(command: string, finding: Finding): string | null {
	if (finding.kind === "protected-path" || finding.severity === "critical") return null;
	let policy: { allowUntil?: unknown; allow?: unknown };
	try {
		policy = JSON.parse(readFileSync(POLICY_FILE, "utf8"));
	} catch {
		return null;
	}
	if (typeof policy.allowUntil === "string") {
		const until = Date.parse(policy.allowUntil);
		if (!Number.isFinite(until) || Date.now() > until) return null; // 过期就整体失效
	}
	for (const entry of Array.isArray(policy.allow) ? policy.allow : []) {
		const pattern = (entry as { commandRe?: unknown })?.commandRe;
		if (typeof pattern !== "string") continue;
		try {
			if (new RegExp(pattern).test(command)) return pattern;
		} catch {
			// 坏正则忽略，不影响其它条目
		}
	}
	return null;
}

/**
 * 终端确认 + 超时。无人应答时返回 "timeout"（按拒绝执行），
 * 这样工具调用失败、会话继续，而不是整场挂在这一步。
 * 定时器在人回答后必须清掉，否则会在几百毫秒后补一条假超时通知。
 */
async function askTerminal(
	ctx: { ui: { confirm: (title: string, message: string) => Promise<boolean>; notify: (m: string, type?: "info" | "warning" | "error") => void } },
	title: string,
	message: string,
): Promise<"approved" | "denied" | "timeout"> {
	const seconds = Math.max(1, Math.round(TERMINAL_TIMEOUT_MS / 1000));
	return new Promise<"approved" | "denied" | "timeout">((resolve) => {
		let settled = false;
		const finish = (verdict: "approved" | "denied" | "timeout") => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve(verdict);
		};
		const timer = setTimeout(() => {
			ctx.ui.notify(`safety-gate: ${seconds}s 无人确认，按拒绝处理（这条命令失败，会话继续）`, "warning");
			finish("timeout");
		}, TERMINAL_TIMEOUT_MS);
		(timer as unknown as { unref?: () => void }).unref?.();
		ctx.ui
			.confirm(title, message)
			.then((yes) => finish(yes ? "approved" : "denied"))
			.catch(() => finish("denied"));
	});
}

/**
 * Write-then-rename: pending.json is read concurrently by the eink viewer and by
 * the pi that parks it, and a half-written file reads as "nothing pending".
 */
function writeJsonAtomic(file: string, value: unknown): void {
	const tmp = `${file}.${process.pid}.tmp`;
	writeFileSync(tmp, JSON.stringify(value));
	renameSync(tmp, file);
}

/** True when the e-ink bridge is up, i.e. the Kindle page can answer for us. */
const STATE_MAX_AGE_MS = 5 * 60_000;
const STALE_ANSWER_MS = 10 * 60_000;

/** A pid can be reused, so liveness alone is not proof: pair it with a fresh timestamp. */
function processAlive(pid: unknown): boolean {
	if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch (err) {
		// EPERM means the process exists but belongs to another user
		return (err as NodeJS.ErrnoException)?.code === "EPERM";
	}
}

function fresh(updatedAt: unknown): boolean {
	if (typeof updatedAt !== "string") return false;
	const age = Date.now() - new Date(updatedAt).getTime();
	return Number.isFinite(age) && age <= STATE_MAX_AGE_MS;
}

/**
 * True when THIS process serves a bridge, so the Kindle page is showing our session.
 * Every session registers in bridges.json; bridge.json only holds whichever
 * session wrote it last, so it cannot answer "am I bridged?" with several pi
 * sessions running.
 */
function bridgeActive(): boolean {
	try {
		const reg = JSON.parse(readFileSync(BRIDGES_FILE, "utf8")) as Record<string, { pid?: number; updatedAt?: string }>;
		for (const entry of Object.values(reg ?? {})) {
			if (entry?.pid === process.pid && fresh(entry.updatedAt)) return true;
		}
		return false;
	} catch {
		return false;
	}
}

function dropIfStale(id?: string): void {
	try {
		const pending = JSON.parse(readFileSync(PENDING_FILE, "utf8")) as { id?: string };
		if (id !== undefined && pending?.id !== id) return;
		unlinkSync(PENDING_FILE);
	} catch {
		// already gone
	}
}

/**
 * A pending request means another command is already waiting — but only while the
 * process that parked it is alive and the request has not expired. A pi killed
 * mid-approval leaves the file behind; without this check every risky command
 * would be refused for the next two minutes with "另一条危险命令正在等待".
 */
function pendingBusy(): boolean {
	try {
		const pending = JSON.parse(readFileSync(PENDING_FILE, "utf8")) as {
			at?: number;
			timeoutMs?: number;
			pid?: number;
		};
		const timeout = pending.timeoutMs ?? REMOTE_TIMEOUT_MS;
		const expired = Date.now() - (pending.at ?? 0) >= timeout + 5000;
		if (expired || !processAlive(pending.pid)) {
			dropIfStale();
			return false;
		}
		return true;
	} catch {
		return false;
	}
}

/**
 * Park the command for the Kindle page and wait for a yes/no there.
 * Returns undefined when the bridge is unavailable so the caller can fall back
 * to the terminal dialog.
 */
async function remoteConfirm(
	ctx: { ui: { notify: (message: string, type?: "info" | "warning" | "error") => void } },
	reason: string,
	command: string,
	signal?: AbortSignal,
): Promise<"approved" | "denied" | "busy" | "cancelled" | undefined> {
	if (signal?.aborted) return "cancelled";
	if (!bridgeActive()) return undefined;

	if (pendingBusy()) return "busy";

	const id = randomUUID();
	try {
		// a leftover answer from a timed-out request must not be mistaken for this one
		try {
			const stale = Date.now() - statSync(ANSWER_FILE).mtimeMs;
			if (stale > STALE_ANSWER_MS) unlinkSync(ANSWER_FILE);
		} catch {
			// no answer file
		}
		writeJsonAtomic(PENDING_FILE, {
			id,
			// pending.json is shared by every pi process; the bridge accepts an answer
			// only for a request parked by its own pid.
			pid: process.pid,
			reason,
			command,
			at: Date.now(),
			timeoutMs: REMOTE_TIMEOUT_MS,
		});
	} catch {
		return undefined;
	}

	ctx.ui.notify(
		`safety-gate: 等待确认（终端或 Kindle 谁先都算，${REMOTE_TIMEOUT_MS / 1000}s 后自动拒绝）: ${reason}`,
		"warning",
	);

	const deadline = Date.now() + REMOTE_TIMEOUT_MS;
	try {
		while (Date.now() < deadline) {
			await new Promise((resolve) => setTimeout(resolve, 400));
			// the terminal dialog may have been answered first
			if (signal?.aborted) return "cancelled";
			try {
				const answer = JSON.parse(readFileSync(ANSWER_FILE, "utf8")) as { id?: string; approved?: boolean };
				if (answer?.id === id) {
					try {
						unlinkSync(ANSWER_FILE);
					} catch {
						// already gone
					}
					return answer.approved === true ? "approved" : "denied";
				}
			} catch {
				// no answer yet
			}
		}
		return "denied"; // timeout denies, never allows
	} finally {
		try {
			const still = JSON.parse(readFileSync(PENDING_FILE, "utf8")) as { id?: string };
			if (still?.id === id) unlinkSync(PENDING_FILE);
		} catch {
			// already cleaned up
		}
	}
}

/**
 * Offer the command on both channels at once and take whichever answers first.
 * The Kindle is the point of this extension, but waiting alone at the terminal
 * for two minutes when nobody picks up the e-reader is worse than useless.
 */
async function decide(
	ctx: { hasUI: boolean; ui: { confirm: (title: string, message: string, opts?: { signal?: AbortSignal }) => Promise<boolean>; notify: (m: string, type?: "info" | "warning" | "error") => void } },
	title: string,
	message: string,
	kindleReason: string,
	command: string,
): Promise<"approved" | "denied" | "busy" | "timeout"> {
	if (!bridgeActive()) {
		if (!ctx.hasUI) return "denied";
		const verdict = await askTerminal(ctx, title, message);
		return verdict;
	}
	if (pendingBusy()) {
		// another command is already on the Kindle page: terminal only
		if (!ctx.hasUI) return "busy";
		return await askTerminal(ctx, title, message);
	}

	const aborter = new AbortController();
	const terminal: Promise<"approved" | "denied"> = ctx.hasUI
		? ctx.ui.confirm(title, message, { signal: aborter.signal })
			.then((yes): "approved" | "denied" => (yes ? "approved" : "denied"))
			.catch(() => "denied" as const)
		// No UI: the Kindle is the only channel, so this must never settle — a
		// resolved "denied" here wins the race before the Kindle gets its turn.
		: new Promise<"approved" | "denied">(() => {});

	// The bridge can come back "unavailable"/"busy" instead of a verdict. That must
	// not decide anything: fall through to the terminal, which is still open.
	const kindle = remoteConfirm(ctx, kindleReason, command, aborter.signal).then((v) =>
		v === "approved" || v === "denied" ? v : terminal);

	const winner = await Promise.race([kindle, terminal]);
	aborter.abort();  // dismiss the losing dialog / stop the pending poll
	// the Kindle poll loop notices the abort on its next tick; drop the file now so
	// the page never shows a confirmation whose tool call has already been decided
	try {
		const still = JSON.parse(readFileSync(PENDING_FILE, "utf8")) as { pid?: number };
		if (still?.pid === process.pid) unlinkSync(PENDING_FILE);
	} catch {
		// nothing parked, or another session owns it
	}
	if (winner === "approved" || winner === "denied") return winner;
	if (winner === "busy") return "busy";
	return "denied";  // cancelled or bridge vanished: default deny
}

/** 命令太长时只展示开头，避免把确认框或 Kindle 页面撑爆。 */
function clipCommand(command: string): string {
	return command.length > 400 ? `${command.slice(0, 400)}\u2026` : command;
}

/**
 * 终端里的提示。critical 必须让人看见「要动哪些东西」，
 * 并且第二次确认才说最狠的那句话 —— 第一次就把话说满会让人麻木。
 */
function terminalMessage(finding: Finding, command: string, pass: number, total: number): string {
	const cmd = clipCommand(command);
	if (finding.severity !== "critical") {
		return `${finding.reason}\n\n  ${cmd}\n\n允许这条命令吗？（终端或 Kindle 谁先确认都算）`;
	}
	const lines = [finding.reason, ""];
	if (finding.evidence && finding.evidence.length > 0) {
		lines.push("目标：");
		for (const item of finding.evidence.slice(0, 8)) lines.push(`  \u2022 ${item}`);
		const rest = finding.evidence.length - 8;
		if (rest > 0) lines.push(`  \u2026还有 ${rest} 个`);
		lines.push("");
	}
	lines.push("命令：");
	lines.push(`  ${cmd}`);
	lines.push("");
	lines.push(
		pass === 1
			? "继续？批准后还会再确认一次。"
			: "最后一次确认：不可撤销（不进废纸篓）。执行吗？",
	);
	return lines.join("\n");
}

/** Kindle 页面上只有一行位置，所以这里压成一行。 */
function kindleReason(finding: Finding, pass: number, total: number): string {
	const prefix = total > 1 ? `[${pass}/${total}] ` : "";
	if (finding.severity !== "critical" || !finding.evidence || finding.evidence.length === 0) {
		return prefix + finding.reason;
	}
	const shown = finding.evidence.slice(0, 3).join("；");
	const rest = finding.evidence.length - 3;
	return `${prefix}${finding.reason}｜${shown}${rest > 0 ? `；…另 ${rest} 个` : ""}`;
}

export default function (pi: ExtensionAPI) {
	pi.on("session_start", async () => {
		pruneTrash();
		rotateGateLog();
	});

	pi.on("tool_call", async (event, ctx) => {
		const cwd = ctx.cwd ?? process.cwd();

		if (event.toolName === "write" || event.toolName === "edit") {
			const path = event.input.path as string;
			if (typeof path !== "string") return undefined;

			const hit = findProtectedPath(path, cwd);
			if (!hit) return undefined;

			if (ctx.hasUI) {
				ctx.ui.notify(`Blocked write to protected path: ${path}`, "warning");
			}
			return { block: true, reason: `Path "${path}" is protected (${hit})` };
		}

		if (event.toolName === "bash") {
			const command = event.input.command as string;
			if (typeof command !== "string") return undefined;

			const finding = analyzeCommand(command, cwd);
			if (!finding) return undefined;

			// unparsed 只是引号不闭合（解析器限制），不是风险信号；
			// 可解析的片段已逐段查过，没命中就不该拦。
			if (finding.kind === "unparsed") {
				if (ctx.hasUI) {
					ctx.ui.notify(`safety-gate: ${finding.reason}（已放行）`, "info");
				}
				return undefined;
			}

			if (!ctx.hasUI) {
				return { block: true, reason: `Blocked with no UI to confirm (${finding.kind}): ${finding.reason}` };
			}

			// 0) 凭据文件：连确认都不给
			if (finding.hardBlock) {
				logGate(`hard-block :: ${command}`);
				if (ctx.hasUI) ctx.ui.notify(`safety-gate: 拒绝触碰 pi 凭据（${finding.reason}）`, "error");
				return { block: true, reason: `Blocked (credentials): ${finding.reason}` };
			}

			// 1) 离开前预授权过的命令，不打扰
			const allowed = policyHit(command, finding);
			if (allowed !== null) {
				logGate(`policy-allow ${allowed} :: ${command}`);
				if (ctx.hasUI) ctx.ui.notify(`safety-gate: 预授权放行（${allowed}）`, "info");
				return undefined;
			}

			// 2) cwd 内的简单删除改写成「移入废纸篓」：可恢复，就不必问
			if (finding.rm) {
				const plan = planTrashRewrite(command, cwd, trashDirFor());
				if (plan) {
					event.input.command = plan.command;
					logGate(`trash ${plan.targets.join(" ")} -> ${plan.command}`);
					if (ctx.hasUI) {
						ctx.ui.notify(`safety-gate: 删除已改写为移入废纸篓（可恢复）：${plan.targets.join(" ")}`, "info");
					}
					return undefined;
				}
			}

			const total = finding.severity === "critical" ? 2 : 1;
			ctx.ui.notify(
				finding.severity === "critical"
					? `⚠️ safety-gate: 高危（需 ${total} 次确认）— ${finding.reason}`
					: `⚠️ safety-gate: ${finding.reason}`,
				"warning",
			);
			for (let pass = 1; pass <= total; pass++) {
				const title = `⚠️ safety-gate${total > 1 ? ` · ${pass}/${total}` : ""}`;
				const verdict = await decide(
					ctx,
					title,
					terminalMessage(finding, command, pass, total),
					kindleReason(finding, pass, total),
					command,
				);
				if (verdict === "busy") {
					return { block: true, reason: `Blocked: 另一条危险命令正在等待 Kindle 确认（${finding.reason}）` };
				}
				if (verdict === "timeout") {
					return {
						block: true,
						reason: `Blocked (no answer in ${Math.max(1, Math.round(TERMINAL_TIMEOUT_MS / 1000))}s, treated as deny)${total > 1 ? ` at pass ${pass}/${total}` : ""}: ${finding.reason}`,
					};
				}
				if (verdict !== "approved") {
					return {
						block: true,
						reason: `Blocked by user${total > 1 ? ` (pass ${pass}/${total})` : ""}: ${finding.reason}`,
					};
				}
			}
			return undefined;
		}

		return undefined;
	});
}
