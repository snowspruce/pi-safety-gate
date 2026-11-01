/**
 * Safety Gate — pure rule engine.
 *
 * 这里刻意不 import `pi`，因此可以在 agent 之外直接单测：
 *   node --experimental-strip-types rules.test.ts
 *
 * 威胁模型：这是针对「agent 犯错」和「提示注入」的护栏，不是沙箱。
 * 它有意做保守的过度近似（over-approximate），但误报率必须低到可以常开。
 *
 * 相对旧版（三个裸正则）的改动：
 *   1. 引号感知分词 —— `echo 'rm -rf'` 不再误报，`rm -r''f` 这类引号逃逸仍能识别
 *   2. 命令结构化解析 —— 按 `;`/`&&`/`||`/`|`/换行 切分，剥离 env 赋值与 wrapper
 *   3. bash 也检查受保护路径 —— 堵住 `echo x > node_modules/f` 这个旧缺口
 *   4. 路径按 segment 判定 —— `.env.example` / `.github/` 不再误伤
 */

import { readdirSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, normalize, resolve, sep } from "node:path";

export type FindingKind = "dangerous-command" | "protected-path" | "unparsed";

/**
 * 分级由「后果有多不可逆 + 范围有多大」决定，不是由命令多吓人决定：
 *   critical  —— 范围不可预期或落在工作目录之外（大量文件 / 多目标 / 通配 / 根级）。
 *                确认框会列出目标与规模，并且要二次确认。
 *   dangerous —— 语义明确的破坏动作（强推、reset --hard、提权、写设备）。一次确认，文案简短。
 *   notice    —— 只是「无法完全核验」，不构成破坏证据（引号不闭合）。只提示，不拦。
 */
export type Severity = "critical" | "dangerous" | "notice";

export interface Finding {
	kind: FindingKind;
	severity: Severity;
	/** 展示在确认框 / block reason 里的说明。 */
	reason: string;
	/** 只有 critical 会填：每行一个目标，带位置与规模，让人看清「到底要删什么」。 */
	evidence?: string[];
	/** 凭据类文件：bash 也不给确认，直接阻断。 */
	hardBlock?: boolean;
	/** rm 的结构化信息：index.ts 用它决定能否把删除改写成「移入废纸篓」。 */
	rm?: { targets: string[]; recursive: boolean; force: boolean };
}

// ---------------------------------------------------------------------------
// 受保护路径
// ---------------------------------------------------------------------------

/** 目录名（任一 segment 命中即受保护）。`.gitignore` 的 segment 是 `.gitignore`，不会命中 `.git`。 */
const PROTECTED_DIR_SEGMENTS = new Set(["node_modules", ".git", ".ssh", ".aws", ".gnupg"]);

/** `.env.*` 的例外后缀：这些是模板，本来就该被编辑。 */
const ENV_TEMPLATE_SUFFIXES = new Set(["example", "sample", "template", "dist", "test", "schema", "defaults"]);

/**
 * 绝对前缀保护。只按目录名（PROTECTED_DIR_SEGMENTS）挡不住这些：
 *   ~/.pi/agent —— 本门禁的源码（safety-gate/）、settings.json、auth.json、其它扩展
 *   ~/.pi/eink  —— token / pin / allow_ips 等凭据
 * agent 能改门禁就等于没有门禁；能读 token 就等于能远程操控这个会话。
 */
const PROTECTED_ROOTS: readonly string[] = [
	join(homedir(), ".pi", "agent"),
	join(homedir(), ".pi", "eink"),
];

/** 废纸篓：清理它属于设计用途，不算"破坏数据"，也不该受 ~/.pi/eink 保护。 */
const TRASH_ROOT = join(homedir(), ".pi", "eink", "trash");
const EINK_HOME = join(homedir(), ".pi", "eink");
/**
 * eink 目录里可以随手删的东西：日志（纯诊断、丢了不影响功能）。
 * 注意只认 `*.log` 后缀，`rm -rf ~/.pi/eink/*` 里的 token 依然受保护。
 */
const DISPOSABLE_SUFFIX = /\.log(\.\d+)?$/;
const EINK_CREDENTIAL_FILES = new Set(["token", "pin", "masked_secrets"]);

function isDisposableEinkPath(abs: string): boolean {
	if (abs !== EINK_HOME && !abs.startsWith(EINK_HOME + sep)) return false;
	if (abs === TRASH_ROOT || abs.startsWith(TRASH_ROOT + sep)) return true;
	return DISPOSABLE_SUFFIX.test(abs);
}

/** 用户级缓存根目录。 */
const CACHE_ROOTS: readonly string[] = [join(homedir(), "Library", "Caches"), join(homedir(), ".cache")];
/**
 * 名字本身就说明是缓存的目录（构建/测试产物，删了重建即可）。
 * 刻意不收 `dist` / `build` / `.next`：项目里可能有同名的源码目录。
 */
const CACHE_DIR_NAMES = new Set([
	"__pycache__",
	".pytest_cache",
	".mypy_cache",
	".ruff_cache",
	".turbo",
	".parcel-cache",
	".svelte-kit",
]);

function isRegenerableCache(abs: string): boolean {
	for (const root of CACHE_ROOTS) {
		if (abs === root || abs.startsWith(root + sep)) return true;
	}
	const segments = abs.split(sep).filter(Boolean);
	const base = segments[segments.length - 1] ?? "";
	if (CACHE_DIR_NAMES.has(base)) return true;
	if (abs.includes(`${sep}node_modules${sep}.cache`)) return true;
	if (abs.includes(`${sep}.next${sep}cache`)) return true;
	return false;
}

/** pi 的凭据文件：agent 没有任何正当理由去删改它们。 */
function isCredentialPath(abs: string): boolean {
	if (abs === join(homedir(), ".pi", "agent", "auth.json")) return true;
	if (abs !== EINK_HOME && !abs.startsWith(EINK_HOME + sep)) return false;
	return EINK_CREDENTIAL_FILES.has(abs.slice(EINK_HOME.length + 1));
}

/**
 * 目标是否落在废纸篓里。允许目标带通配符（`rm -rf ~/.pi/eink/trash/*` 是标准清理写法），
 * 只按字面前缀判断；`trash/../token` 这类会被 normalize 拆穿。
 */
export function isTrashTarget(raw: string, cwd: string): boolean {
	const expanded = expandHome(raw);
	const abs = normalize(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
	return abs === TRASH_ROOT || abs.startsWith(TRASH_ROOT + sep);
}

function protectedRootHit(abs: string): string | null {
	if (isDisposableEinkPath(abs)) return null;
	for (const root of PROTECTED_ROOTS) {
		if (abs !== root && !abs.startsWith(root + sep)) continue;
		return abs.includes(`${sep}extensions${sep}`)
			? `lives in ${root} — pi extension code, including this gate itself`
			: `lives in ${root} — pi configuration and credentials`;
	}
	return null;
}

function expandHome(p: string): string {
	if (p === "~") return homedir();
	if (p.startsWith("~/")) return join(homedir(), p.slice(2));
	return p;
}

/**
 * 返回命中的原因说明；未命中返回 null。
 * `rawPath` 可以是相对路径（相对 `cwd` 解析）或 `~` 开头。
 */
export function findProtectedPath(rawPath: string, cwd: string): string | null {
	if (typeof rawPath !== "string" || rawPath.trim() === "") return null;

	const expanded = expandHome(rawPath.trim());
	const abs = normalize(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
	const segments = abs.split(sep).filter(Boolean);
	const base = segments[segments.length - 1] ?? "";

	if (isRegenerableCache(abs)) return null; // node_modules/.cache、__pycache__ 之类先放行

	for (const segment of segments) {
		if (PROTECTED_DIR_SEGMENTS.has(segment)) {
			return `"${segment}" is a protected directory`;
		}
	}

	const rootHit = protectedRootHit(abs);
	if (rootHit) return rootHit;

	if (/^\.env(\..+)?$/i.test(base)) {
		const suffix = base.split(".").slice(2).join(".").toLowerCase();
		if (!ENV_TEMPLATE_SUFFIXES.has(suffix)) return "env file may contain secrets";
	}

	if (/^id_(rsa|dsa|ecdsa|ed25519)$/i.test(base) || /\.(pem|key|p12|pfx|keystore|jks)$/i.test(base)) {
		return "looks like a private key or certificate";
	}

	return null;
}

/** `/dev/null` 之类的无害设备不算写入风险；`/dev/disk2` 之类算。 */
function isDeviceWrite(target: string): boolean {
	return /^\/dev\//.test(target) && !/^\/dev\/(null|stdout|stderr|tty|zero|random|urandom|fd\/)/.test(target);
}

// ---------------------------------------------------------------------------
// Shell 解析
// ---------------------------------------------------------------------------

const QUOTES = new Set(["'", '"']);

/**
 * 按顶层 `;` `&&` `||` `|` `&` `(` `)` 换行 切分，引号内的分隔符不切。
 * 返回 balanced=false 表示引号不闭合 —— 无法安全判定，调用方应保守处理。
 */
export function splitCommands(input: string): { parts: string[]; separators: string[]; balanced: boolean } {
	const parts: string[] = [];
	const separators: string[] = [];
	let current = "";
	let quote: string | null = null;

	for (let i = 0; i < input.length; i++) {
		const ch = input[i];

		if (quote) {
			if (ch === "\\" && quote === '"' && i + 1 < input.length) {
				current += ch + input[++i];
				continue;
			}
			if (ch === quote) quote = null;
			current += ch;
			continue;
		}

		if (ch === "\\" && i + 1 < input.length) {
			current += ch + input[++i];
			continue;
		}

		if (QUOTES.has(ch)) {
			quote = ch;
			current += ch;
			continue;
		}

		if (ch === "\n" || ch === ";" || ch === "|" || ch === "&" || ch === "(" || ch === ")") {
			let separator = ch;
			if ((ch === "|" || ch === "&") && input[i + 1] === ch) {
				separator += ch;
				i++;
			}
			parts.push(current);
			separators.push(separator);
			current = "";
			continue;
		}

		current += ch;
	}

	parts.push(current);
	return { parts, separators, balanced: quote === null };
}

/**
 * 把单个简单命令切成 token，**剥掉引号**。
 * 因此 `rm "-rf"` 与 `rm -r''f` 都会归一成 token `-rf`。
 */
export function tokenize(input: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let quote: string | null = null;
	let started = false;

	for (let i = 0; i < input.length; i++) {
		const ch = input[i];

		if (quote) {
			if (ch === "\\" && quote === '"' && i + 1 < input.length) {
				current += input[++i];
				continue;
			}
			if (ch === quote) {
				quote = null;
				continue;
			}
			current += ch;
			continue;
		}

		if (ch === "\\" && i + 1 < input.length) {
			current += input[++i];
			continue;
		}

		if (QUOTES.has(ch)) {
			quote = ch;
			started = true;
			continue;
		}

		if (ch === " " || ch === "\t") {
			if (started || current !== "") {
				tokens.push(current);
				current = "";
				started = false;
			}
			continue;
		}

		current += ch;
	}

	if (started || current !== "") tokens.push(current);
	return tokens;
}

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const REDIRECT = /^(?:\d+)?(?:>>|>\||>)(.*)$/;

function basenameOf(token: string): string {
	const parts = token.split("/");
	return parts[parts.length - 1] ?? token;
}

/** 收集 `>` `>>` `>|` 的写入目标（跳过 `2>&1` 这类 fd 复制）。 */
function redirectTargets(tokens: string[]): string[] {
	const targets: string[] = [];
	for (let i = 0; i < tokens.length; i++) {
		const match = REDIRECT.exec(tokens[i]);
		if (!match) continue;
		const inline = match[1];
		if (inline) {
			if (!inline.startsWith("&")) targets.push(inline);
		} else if (tokens[i + 1] !== undefined) {
			targets.push(tokens[++i]);
		}
	}
	return targets;
}

/** wrapper 会掩盖真正的命令名，需要剥掉后继续解析。 */
const WRAPPERS = new Set(["command", "builtin", "env", "nohup", "nice", "time", "stdbuf", "exec", "setsid", "ionice"]);
const ELEVATORS = new Set(["sudo", "doas", "su", "runas", "pkexec"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);
const INTERPRETERS = new Set(["python", "python2", "python3", "node", "perl", "ruby", "php"]);
const FILESYSTEM_DESTROYERS = new Set([
	"mkfs",
	"newfs",
	"wipefs",
	"fdisk",
	"parted",
	"shred",
	"diskutil",
	"shutdown",
	"reboot",
	"halt",
	"poweroff",
]);

const DANGEROUS_ROOTS = new Set(["/", "/*", "~", "~/", "*", ".", "..", "$HOME", "${HOME}", "$home"]);
const DANGEROUS_ROOT_PREFIX = /^\/(bin|sbin|etc|usr|var|System|Library|Applications|Users|home|opt|dev|boot)\b/;

function isDangerousRoot(target: string): boolean {
	return DANGEROUS_ROOTS.has(target) || DANGEROUS_ROOT_PREFIX.test(target);
}

function hasShortFlag(args: string[], flag: string): boolean {
	const pattern = new RegExp(`^-[a-z]*${flag}[a-z]*$`, "i");
	return args.some((a) => pattern.test(a));
}

function hasExactFlag(args: string[], ...flags: string[]): boolean {
	return args.some((a) => flags.includes(a));
}

/**
 * 只有像路径的 token 才值得检查受保护路径。
 * heredoc/引号/正则里漏出来的 `=`, `0`, `s/x/y/` 这类片段报到用户面前全是噪音。
 */
function looksLikePath(token: string): boolean {
	if (token === "" || token === "-") return false;
	if (/^[=+0-9.,:;!?*%$#@^&|<>()[\]{}~]+$/.test(token)) return false;
	return /[\w.-]/.test(token);
}

/** 该命令会写入哪些路径（用于受保护路径检查）。 */
export function collectWriteTargets(command: string, args: string[], tokens: string[]): string[] {
	const targets: string[] = redirectTargets(tokens);
	const positional = args.filter((a) => !a.startsWith("-"));

	switch (command) {
		case "tee":
		case "truncate":
			targets.push(...positional);
			break;
		case "cp":
		case "mv":
		case "install":
		case "rsync":
		case "ln":
			if (positional.length > 0) targets.push(positional[positional.length - 1]);
			break;
		case "rm":
		case "rmdir":
		case "shred":
			targets.push(...positional);
			break;
		case "sed":
		case "perl":
			// `sed -i 's|a|b|' f`：第一个位置参数是脚本，不是路径。
			// 把脚本当写入目标会误报「写受保护路径」——真实踩过：改门禁自己的测试文件被自己拦下。
			if (hasExactFlag(args, "-i") || args.some((a) => a.startsWith("-i"))) {
				// macOS 的 `sed -i '' 's/x/y/' f` 会把空串当独立参数传进来，先剔掉再取路径
				const nonEmpty = positional.filter((arg) => arg !== "");
				targets.push(...nonEmpty.slice(1));
			}
			break;
		case "dd":
			for (const arg of args) {
				if (arg.startsWith("of=")) targets.push(arg.slice(3));
			}
			break;
		default:
			break;
	}

	return targets;
}

// ---------------------------------------------------------------------------
// 命令分类
// ---------------------------------------------------------------------------

/** 单个目标超过这么多项，一次删除就算「大量」。 */
const MASS_FILE_THRESHOLD = 20;
/** 统计上限：确认框必须马上出现，不能为了数文件把 agent 卡在这里。 */
const WALK_LIMIT = 400;
/** 通配符 / 变量：真正删什么由 shell 决定，我们不知道，也不假装知道。 */
const WILDCARD = /[*?\[\]$`]/;

interface TargetProfile {
	raw: string;
	absolute: string;
	exists: boolean;
	files: number;
	truncated: boolean;
	outsideCwd: boolean;
	wildcard: boolean;
	rootLike: boolean;
}

function countEntries(root: string): { files: number; truncated: boolean } {
	let files = 0;
	const stack: string[] = [root];
	while (stack.length > 0) {
		const current = stack.pop() as string;
		let entries;
		try {
			entries = readdirSync(current, { withFileTypes: true });
		} catch {
			continue; // 权限不足 / 已被删 / 正在变：不猜，按看不见处理
		}
		for (const entry of entries) {
			if (files >= WALK_LIMIT) return { files, truncated: true };
			files++;
			if (entry.isDirectory()) stack.push(join(current, entry.name));
		}
	}
	return { files, truncated: false };
}

/** /tmp、$TMPDIR 里的内容按约定就是一次性的，不属于「可能删掉真东西」。 */
function isEphemeralPath(abs: string): boolean {
	const roots = ["/tmp", "/private/tmp", tmpdir()].map((root) => normalize(root));
	return roots.some((root) => abs !== root && abs.startsWith(root + sep));
}

function isInsideCwd(abs: string, cwd: string): boolean {
	const base = resolve(cwd);
	return abs === base || abs.startsWith(base.endsWith(sep) ? base : base + sep);
}

function profileTarget(raw: string, cwd: string): TargetProfile {
	const expanded = expandHome(raw);
	const absolute = normalize(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
	const wildcard = WILDCARD.test(raw);
	let exists = false;
	let isDir = false;
	if (!wildcard) {
		try {
			const stat = statSync(absolute);
			exists = true;
			isDir = stat.isDirectory();
		} catch {
			// 目标不存在（拼错 / 已被删）：只在 evidence 里说明，不当成规模证据
		}
	}
	const counted = exists && isDir ? countEntries(absolute) : { files: 0, truncated: false };
	return {
		raw,
		absolute,
		exists,
		files: counted.files,
		truncated: counted.truncated,
		outsideCwd: !isInsideCwd(absolute, cwd),
		wildcard,
		rootLike: isDangerousRoot(raw),
	};
}

function describeTarget(profile: TargetProfile): string {
	const tags: string[] = [];
	if (profile.wildcard) tags.push("通配符，实际范围由 shell 决定");
	else if (!profile.exists) tags.push("不存在");
	if (profile.outsideCwd) tags.push("⚠ 工作目录外");
	else if (!profile.wildcard) tags.push("工作目录内");
	if (profile.files > 0) tags.push(`${profile.files}${profile.truncated ? "+" : ""} 项`);
	return `${profile.absolute}  ·  ${tags.join(" · ")}`;
}

function analyzeRm(args: string[], cwd: string): Finding | null {
	const recursive = hasShortFlag(args, "r") || hasExactFlag(args, "--recursive");
	const force = hasShortFlag(args, "f") || hasExactFlag(args, "--force");
	const literals = args.filter((a) => !a.startsWith("-"));
	// 清废纸篓是例行维护，不该拦，也不该计入「出 cwd / 大量文件」的判断。
	const disposable = (target: string): boolean => {
		const expanded = expandHome(target);
		const abs = normalize(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
		return isDisposableEinkPath(abs) || isRegenerableCache(abs);
	};
	if (literals.length > 0 && literals.every(disposable)) return null; // 清日志 / 清废纸篓：例行维护
	const trashTargets = literals.filter((target) => isTrashTarget(target, cwd));
	const targets = literals.filter((target) => !isTrashTarget(target, cwd));
	if (trashTargets.length > 0 && targets.length === 0) return null;

	let base: Finding | null = null;
	const risky = targets.find(isDangerousRoot);
	// 混合目标（废纸篓 + 真实路径）不参与「移动进废纸篓」的改写，避免套娃
	const rm = trashTargets.length > 0 ? undefined : { targets, recursive, force };
	if (recursive && force) {
		base = { kind: "dangerous-command", severity: "dangerous", reason: "Recursive force delete (rm -rf)", rm };
	} else if (recursive && risky !== undefined) {
		base = {
			kind: "dangerous-command",
			severity: "dangerous",
			reason: `Recursive delete of a root-level path ("${risky}")`,
			rm,
		};
	} else if (force && risky !== undefined) {
		base = {
			kind: "dangerous-command",
			severity: "dangerous",
			reason: `Force delete of a root-level path ("${risky}")`,
			rm,
		};
	}
	if (!base) return null;

	// 只有已经判定危险之后才去量范围：普通 rm 不承担任何 IO 代价。
	const profiles = targets.map((target) => profileTarget(target, cwd));
	const scope: string[] = [];
	if (profiles.length >= 2) scope.push(`${profiles.length} 个独立目标`);
	const outside = profiles.filter(
		(profile) => profile.outsideCwd && !isEphemeralPath(profile.absolute) && !isRegenerableCache(profile.absolute),
	);
	if (outside.length > 0) scope.push(`${outside.length} 个在工作目录之外`);
	if (profiles.some((profile) => profile.wildcard)) scope.push("含通配符");
	if (profiles.some((profile) => profile.rootLike)) scope.push("落在系统级目录（/Users、/usr、/etc 等）");
	if (profiles.some((profile) => profile.files >= MASS_FILE_THRESHOLD)) {
		scope.push(`单个目标 ≥ ${MASS_FILE_THRESHOLD} 项`);
	}

	if (scope.length === 0) return base;
	return {
		...base,
		severity: "critical",
		reason: `${base.reason} — ${scope.join("，")}`,
		evidence: profiles.map(describeTarget),
	};
}

/** `git -C <path> push`：这些全局 flag 带值，取值时不能误当成子命令。 */
const GIT_GLOBAL_FLAGS_WITH_VALUE = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"]);

function analyzeGit(args: string[]): Finding | null {
	let subcommand: string | undefined;
	for (let i = 0; i < args.length; i++) {
		if (GIT_GLOBAL_FLAGS_WITH_VALUE.has(args[i])) {
			i++;
			continue;
		}
		if (!args[i].startsWith("-")) {
			subcommand = args[i];
			break;
		}
	}

	// --dry-run / -n 明确不写远端：强制推送的规则不该把它也拦下来。
	const dryRun = hasExactFlag(args, "--dry-run") || args.includes("-n");
	if (subcommand === "push" && !dryRun && (hasShortFlag(args, "f") || hasExactFlag(args, "--force"))) {
		return { kind: "dangerous-command", severity: "dangerous", reason: "Force push overwrites remote history (use --force-with-lease)" };
	}
	if (subcommand === "reset" && hasExactFlag(args, "--hard")) {
		return { kind: "dangerous-command", severity: "dangerous", reason: "git reset --hard discards uncommitted work" };
	}
	if (subcommand === "clean" && hasShortFlag(args, "f")) {
		return { kind: "dangerous-command", severity: "dangerous", reason: "git clean -f deletes untracked files" };
	}
	if (subcommand === "branch" && hasExactFlag(args, "-D")) {
		// 删掉的只是 ref，提交还在 reflog 里，能捞回来 → 只提示
		return { kind: "unparsed", severity: "notice", reason: "git branch -D removes a branch ref (recoverable from reflog)" };
	}
	if (subcommand === "checkout" && hasExactFlag(args, "--")) {
		const pathspec = args[args.indexOf("--") + 1];
		if (pathspec === "." || pathspec === "*") {
			return { kind: "dangerous-command", severity: "dangerous", reason: "git checkout -- . discards uncommitted changes" };
		}
	}
	return null;
}

function analyzePermissions(command: string, args: string[]): Finding | null {
	const worldWritable = args.some(
		(a) => /^(0?[0-7])?777$/.test(a) || /^(a|ugo)?\+rwx$/i.test(a) || /^o\+w$/i.test(a) || /^a=rwx$/i.test(a),
	);
	if (worldWritable) {
		return { kind: "dangerous-command", severity: "dangerous", reason: `${command} makes a path world-writable` };
	}
	return null;
}

function analyzeFind(args: string[], cwd: string): Finding | null {
	// find 的搜索根全落在废纸篓/临时目录/缓存里时，-delete 只是清垃圾
	const FIND_VALUE_FLAGS = new Set([
		"-type", "-name", "-iname", "-path", "-ipath", "-maxdepth", "-mindepth", "-mtime", "-mmin",
		"-size", "-newer", "-newermt", "-perm", "-user", "-group", "-regex", "-iregex", "-depth",
	]);
	const roots: string[] = [];
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (FIND_VALUE_FLAGS.has(arg)) {
			i++; // 跳过它的值
			continue;
		}
		if (arg.startsWith("-") || arg === "{}" || arg === ";") continue;
		roots.push(arg);
	}
	const disposableRoots =
		roots.length > 0 &&
		roots.every((arg) => {
			const expanded = expandHome(arg);
			const abs = normalize(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
			return isDisposableEinkPath(abs) || isEphemeralPath(abs) || isRegenerableCache(abs);
		});
	if (disposableRoots) return null;

	if (args.includes("-delete")) {
		return { kind: "dangerous-command", severity: "dangerous", reason: "find -delete deletes every match" };
	}
	const execIndex = args.indexOf("-exec");
	if (execIndex >= 0) {
		const inner = args.slice(execIndex + 1).find((a) => !a.startsWith("-") && a !== "{}" && a !== ";");
		if (inner !== undefined && ["rm", "rmdir", "shred", "truncate"].includes(basenameOf(inner))) {
			return { kind: "dangerous-command", severity: "dangerous", reason: `find -exec ${basenameOf(inner)} deletes every match` };
		}
	}
	return null;
}

/** 从 `sh -c` / `eval` / `xargs` / `python -c` 里取出待执行的载荷。 */
function extractPayload(command: string, args: string[]): string | null {
	if (SHELLS.has(command)) {
		const index = args.findIndex((a) => a === "-c" || /^-[a-z]*c[a-z]*$/i.test(a));
		if (index >= 0 && args[index + 1] !== undefined) return args.slice(index + 1).join(" ");
		return null;
	}
	if (INTERPRETERS.has(command)) {
		const index = args.findIndex((a) => a === "-c" || a === "-e");
		if (index >= 0 && args[index + 1] !== undefined) return args.slice(index + 1).join(" ");
		return null;
	}
	if (command === "eval") return args.join(" ");
	if (command === "xargs") {
		// 只剥掉命令名之前的 flag；命令名之后的 flag（如 `xargs rm -rf` 的 -rf）属于载荷。
		const XARGS_VALUE_FLAGS = new Set(["-I", "-n", "-P", "-L", "-s", "-E", "-d", "-a"]);
		const XARGS_LONG_VALUE_FLAGS = new Set(["--replace", "--max-args", "--max-procs", "--max-lines", "--delimiter"]);
		let i = 0;
		while (i < args.length && args[i].startsWith("-")) {
			const takesValue =
				XARGS_VALUE_FLAGS.has(args[i]) ||
				XARGS_LONG_VALUE_FLAGS.has(args[i]) ||
				args[i].startsWith("--replace=") ||
				args[i].startsWith("--max-args=");
			i += takesValue && !args[i].includes("=") ? 2 : 1;
		}
		const remainder = args.slice(i);
		return remainder.length > 0 ? remainder.join(" ") : null;
	}
	return null;
}

/**
 * `node -e` / `python -c` 的内联代码是黑盒：递归分析看不懂 `fs.rmSync`。
 * 这里只认「破坏性 API」这一小撮形状——宁可漏（还有 OS 边界兜底），
 * 不要把 `node -e 'console.log(1)'` 这种日常命令也变成确认框。
 */
const DESTRUCTIVE_INLINE_CODE =
	/(rmSync|rmdirSync|unlinkSync|truncateSync|shutil\.rmtree|os\.remove|os\.rmdir|os\.unlink|os\.system|subprocess\.(run|call|Popen|check_output)|child_process|execSync|spawnSync|Deno\.remove|process\.exit)/;

/**
 * `CH="/Applications/.../Chrome"` 之后 `"$CH"` 是常见写法（agent 尤其爱用），
 * 直接报"无法核验"属于误伤。这里收集同一条命令内的字面量赋值并解析。
 * 值里带 `$` 或反引号的不算字面量——那种确实核验不了。
 */
/**
 * 从原始命令文本里扫赋值（不能靠 splitCommands 的片段：它按 `(`/`)` 切开，
 * `TMPH=$(mktemp -d)` 会被拆成 `TMPH=$` + `mktemp -d`，值就丢了）。
 *   - 值里还有 `$` 或反引号 → 不是字面量，跳过
 *   - 值来自 mktemp → 记成临时变量，往它下面写文件按临时目录处理
 */
function scanAssignments(command: string): { literals: Map<string, string>; tempVars: Set<string> } {
	const literals = new Map<string, string>();
	const tempVars = new Set<string>();
	const pattern = /(?:^|[\s;&|(])([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|)]+)/g;
	for (const match of command.matchAll(pattern)) {
		const name = match[1];
		const raw = match[2] ?? "";
		if (/\$\(\s*mktemp\b|`\s*mktemp\b/.test(raw)) {
			tempVars.add(name);
			continue;
		}
		let value = raw.replace(/^["']|["']$/g, "");
		// `$HOME` 是已知常量，先展开；展开后还带 `$`/反引号才放弃
		value = value.replace(/^\$\{?HOME\}?/, homedir());
		if (value === "" || /[$`]/.test(value)) continue;
		literals.set(name, value);
	}
	return { literals, tempVars };
}

/** `$D/profiles/x` → 用 `D=` 的字面量值展开前缀；解析不了返回 null。 */
function expandLeadingVar(token: string, vars: Map<string, string>): string | null {
	const match = /^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))(.*)$/.exec(token);
	if (!match) return null;
	const value = vars.get(match[1] ?? match[2]);
	if (value === undefined) return null;
	return value + (match[3] ?? "");
}

function resolveVar(token: string, vars: Map<string, string>): string | null {
	const match = /^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$/.exec(token);
	if (!match) return null;
	return vars.get(match[1] ?? match[2]) ?? null;
}

/** `cd X` 之后，后续段的工作目录就变了；不跟踪会把 cwd 内的删除误判成"目录外"。 */
function cdTarget(raw: string, cwd: string): string | null {
	const tokens = tokenize(raw);
	if (tokens.length !== 2) return null;
	if (basenameOf(tokens[0]).toLowerCase() !== "cd") return null;
	const target = tokens[1];
	if (target.startsWith("-") || WILDCARD.test(target)) return null;
	const expanded = expandHome(target);
	return normalize(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
}

function analyzeSegment(
	raw: string,
	cwd: string,
	depth: number,
	vars: Map<string, string>,
	tempVars: Set<string>,
): Finding | null {
	const tokens = tokenize(raw);
	if (tokens.length === 0) return null;

	let index = 0;
	while (index < tokens.length && ASSIGNMENT.test(tokens[index])) index++;
	let head = tokens[index];
	let args = tokens.slice(index + 1);
	if (head === undefined) return null;

	// 剥掉 wrapper，露出真正的命令名
	let guard = 0;
	while (WRAPPERS.has(basenameOf(head).toLowerCase()) && guard++ < 8) {
		let skip = 0;
		if (basenameOf(head).toLowerCase() === "env") {
			while (skip < args.length && (ASSIGNMENT.test(args[skip]) || args[skip].startsWith("-"))) skip++;
		}
		if (skip >= args.length) return null;
		head = args[skip];
		args = args.slice(skip + 1);
	}

	let command = basenameOf(head).toLowerCase();

	if (command.includes("$")) {
		const resolved = resolveVar(head, vars);
		if (resolved === null) {
			return {
				kind: "dangerous-command",
				severity: "dangerous",
				reason: `Command name is a variable expansion ("${head}"); cannot verify what will run`,
			};
		}
		head = resolved;
		command = basenameOf(resolved).toLowerCase();
	}

	if (ELEVATORS.has(command)) {
		return { kind: "dangerous-command", severity: "dangerous", reason: `"${command}" runs with elevated privileges` };
	}

	// 嵌套解释器：递归检查载荷
	const payload = extractPayload(command, args);
	if (payload !== null) {
		if (depth >= 3) {
			return { kind: "dangerous-command", severity: "dangerous", reason: "Nested command too deep to verify" };
		}
		if (payload.includes("$") && (command === "eval" || SHELLS.has(command))) {
			return {
				kind: "dangerous-command",
				severity: "dangerous",
				reason: `"${command}" is given a variable payload; cannot verify what will run`,
			};
		}
		const nested = analyzeCommand(payload, cwd, depth + 1);
		if (nested) return nested;
		if (INTERPRETERS.has(command) && DESTRUCTIVE_INLINE_CODE.test(payload)) {
			return {
				kind: "dangerous-command",
				severity: "dangerous",
				reason: `"${command}" runs inline code that deletes or spawns processes; the gate cannot verify it`,
			};
		}
		return null;
	}

	// 写入目标 → 受保护路径 / 设备
	for (const rawTarget of collectWriteTargets(command, args, tokens)) {
		if (!rawTarget.startsWith("$") && !looksLikePath(rawTarget)) continue;
		// `$TMP=$(mktemp -d)` 之后往 $TMP 里写：路径必然在临时目录内
		const tempName = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/.exec(rawTarget)?.[1];
		if (tempName !== undefined && tempVars.has(tempName)) continue;
		const target = rawTarget.startsWith("$")
			? (resolveVar(rawTarget, vars) ?? expandLeadingVar(rawTarget, vars) ?? rawTarget)
			: rawTarget;
		if (target.startsWith("$")) {
			return {
				kind: "dangerous-command",
				severity: "dangerous",
				reason: `Write target is a variable expansion ("${target}"); cannot verify it is safe`,
			};
		}
		if (isDeviceWrite(target)) {
			return { kind: "dangerous-command", severity: "dangerous", reason: `Writes raw data to a device ("${target}")` };
		}
		// 凭据：连确认都不给。删了/写坏了就等于这个会话的远程通道被劫持。
		const expandedTarget = expandHome(target);
		const absTarget = normalize(isAbsolute(expandedTarget) ? expandedTarget : resolve(cwd, expandedTarget));
		if (isCredentialPath(absTarget)) {
			return {
				kind: "protected-path",
				severity: "critical",
				hardBlock: true,
				reason: `Touches a pi credential file ("${target}"); rotate it by hand instead`,
			};
		}
		const hit = findProtectedPath(target, cwd);
		if (hit) {
			return { kind: "protected-path", severity: "dangerous", reason: `Command writes to a protected path: ${target} (${hit})` };
		}
	}

	if (command === "rm") return analyzeRm(args, cwd);
	if (command === "git") return analyzeGit(args);
	if (command === "find") return analyzeFind(args, cwd);
	if (command === "chmod" || command === "chown" || command === "chgrp") return analyzePermissions(command, args);
	if (command === "dd") {
		const output = args.find((a) => a.startsWith("of="));
		if (output) return { kind: "dangerous-command", severity: "dangerous", reason: `dd writes raw data to ${output.slice(3)}` };
		return null;
	}
	if (FILESYSTEM_DESTROYERS.has(command) || command.startsWith("mkfs.") || command.startsWith("newfs_")) {
		return { kind: "dangerous-command", severity: "dangerous", reason: `"${command}" can destroy a filesystem or the host` };
	}
	if (command === "diskutil" && args.some((a) => /^(erase|reformat|deleteVolume|apfs)/i.test(a))) {
		return { kind: "dangerous-command", severity: "dangerous", reason: `"${command} ${args[0]}" erases a volume` };
	}

	return null;
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

/** 检测管道把网络下载直接喂给 shell：`curl ... | sh`。 */
function analyzePipeToShell(parts: string[], separators: string[]): Finding | null {
	for (let i = 0; i < separators.length; i++) {
		if (separators[i] !== "|") continue;
		const leftTokens = tokenize(parts[i] ?? "");
		const rightTokens = tokenize(parts[i + 1] ?? "");
		if (leftTokens.length === 0 || rightTokens.length === 0) continue;
		const left = basenameOf(leftTokens[0]).toLowerCase();
		const right = basenameOf(rightTokens[0]).toLowerCase();
		if (["curl", "wget", "fetch"].includes(left)) {
			// `curl … | sh` 才是执行远程代码；`curl … | python3 -c 'json.load(sys.stdin)'`
			// 只是把下载内容当数据喂给内联程序，源码不在里面的。
			const inlineProgram = rightTokens.slice(1).some((token) => token === "-c" || token === "-e");
			if (SHELLS.has(right)) {
				return {
					kind: "dangerous-command",
					severity: "dangerous",
					reason: `Piping a network download into "${right}" executes remote code`,
				};
			}
			if (INTERPRETERS.has(right) && !inlineProgram) {
				return {
					kind: "dangerous-command",
					severity: "dangerous",
					reason: `Piping a network download into "${right}" executes the downloaded script`,
				};
			}
		}
		// 任何 "… | sh" 都一样：管道左边的内容门禁读不到，内容可以是 rm -rf。
		if (SHELLS.has(right)) {
			return {
				kind: "dangerous-command",
				severity: "dangerous",
				reason: `Piping command output into "${right}"; the gate cannot read what it will run`,
			};
		}
	}
	return null;
}

/** 只有这种朴素 token 才敢拼进改写后的命令：空格/引号/通配/变量一律交回人工。 */
const TRASH_SAFE_TARGET = /^[A-Za-z0-9._@+/-]+$/;

/**
 * 把「一条简单的 rm -rf 目录」改写成「移入废纸篓」，让删除变成可恢复操作。
 * 只处理单条命令、无管道/无分隔符、目标全在 cwd 内、无通配符的情形；
 * 其余（出 cwd、多命令、带通配、路径带空格）一律返回 null，继续走人工确认。
 */
export function planTrashRewrite(
	command: string,
	cwd: string,
	trashDir: string,
): { command: string; targets: string[] } | null {
	const split = splitCommands(command);
	if (split.parts.length === 0) return null;

	/** 单段 `rm -rf <安全目标…>` 才改写；别的段原样保留，cwd 逐段跟踪。 */
	const rewritePart = (part: string, segmentCwd: string): { text: string; targets: string[] } | null => {
		const tokens = tokenize(part);
		if (tokens.length < 2) return null;
		if (basenameOf(tokens[0]).toLowerCase() !== "rm") return null;

		const targets: string[] = [];
		for (const token of tokens.slice(1)) {
			if (token === "--") continue;
			if (token.startsWith("-")) {
				// 只接受 r/f/v 这类无值短选项；-t DIR、--target-directory 会改变语义
				if (!/^-[rRfv]+$/.test(token)) return null;
				continue;
			}
			targets.push(token);
		}
		if (targets.length === 0) return null;

		for (const target of targets) {
			if (!TRASH_SAFE_TARGET.test(target)) return null;
			if (isDangerousRoot(target)) return null;
			const expanded = expandHome(target);
			const abs = normalize(isAbsolute(expanded) ? expanded : resolve(segmentCwd, expanded));
			if (!isInsideCwd(abs, segmentCwd) && !isEphemeralPath(abs)) return null;
			if (abs === resolve(segmentCwd)) return null; // 删 cwd 自己：交给人工
		}
		return {
			text: `mkdir -p '${trashDir}' && mv -- ${targets.join(" ")} '${trashDir}/'`,
			targets,
		};
	};

	// 先确认每个 rm 段都能安全改写：只要有一段落空，就整体不改写，
	// 否则未改写的那段（比如 `rm -rf *`）会跟着改写后的命令一起被放行。
	{
		let probeCwd = cwd;
		for (const part of split.parts) {
			const isRm = basenameOf(tokenize(part)[0] ?? "").toLowerCase() === "rm";
			if (isRm && rewritePart(part, probeCwd) === null) return null;
			const moved = cdTarget(part, probeCwd);
			if (moved !== null) probeCwd = moved;
		}
	}

	let effectiveCwd = cwd;
	let rebuilt = "";
	const allTargets: string[] = [];
	let changed = false;

	for (let i = 0; i < split.parts.length; i++) {
		const part = split.parts[i];
		const rewritten = rewritePart(part, effectiveCwd);
		if (rewritten !== null) {
			rebuilt += rewritten.text;
			allTargets.push(...rewritten.targets);
			changed = true;
		} else {
			rebuilt += part;
		}
		if (i < split.separators.length) rebuilt += split.separators[i];
		const moved = cdTarget(part, effectiveCwd);
		if (moved !== null) effectiveCwd = moved;
	}

	if (!changed) return null;
	return { command: rebuilt, targets: allTargets };
}

/** 同一路径的不同写法（`./x.sh` 与 `x.sh`）要能对上，否则这条规则形同虚设。 */
function canonicalPathForMatch(token: string): string {
	return token.replace(/^\.\//, "").replace(/^"|"$/g, "");
}

/**
 * `printf 'rm -rf ~' > x.sh && sh x.sh`：写和跑在同一条命令里。
 * 逐段看的话两边都"无害"——写入目标不是受保护路径，执行的脚本内容又不在命令文本里。
 */
function analyzeWriteThenRun(parts: string[], command: string, cwd: string, depth: number): Finding | null {
	const written = new Set<string>();
	const bodies = heredocBodies(command);
	for (const part of parts) {
		const tokens = tokenize(part);
		if (tokens.length === 0) continue;

		let index = 0;
		while (index < tokens.length && ASSIGNMENT.test(tokens[index])) index++;
		const head = basenameOf(tokens[index] ?? "").toLowerCase();
		const args = tokens.slice(index + 1);

		if ((SHELLS.has(head) || INTERPRETERS.has(head)) && written.size > 0) {
			const target = args.find((arg) => !arg.startsWith("-"));
			if (target !== undefined && written.has(canonicalPathForMatch(target))) {
				// heredoc 写出来的脚本内容就在命令文本里：分析它，只有真的有风险才拦
				const body = bodies.get(canonicalPathForMatch(target));
				if (body !== undefined && depth < 3) {
					const nested = analyzeCommand(body, cwd, depth + 1);
					if (nested === null || isUnverifiableNoise(nested)) continue;
					return nested;
				}
				return {
					kind: "dangerous-command",
					severity: "dangerous",
					reason: `Writes a script and then runs it in the same command ("${target}"); the gate cannot read what it contains`,
				};
			}
		}

		for (const target of redirectTargets(tokens)) written.add(canonicalPathForMatch(target));
		if (head === "tee") {
			for (const arg of args) if (!arg.startsWith("-")) written.add(canonicalPathForMatch(arg));
		}
	}
	return null;
}

/** `cat > x.py <<'EOF' … EOF`：把文件名与 heredoc 正文配起来。 */
function heredocBodies(command: string): Map<string, string> {
	const bodies = new Map<string, string>();
	const lines = command.split("\n");
	for (let i = 0; i < lines.length; i++) {
		const match = /(?:^|\s)([^\s<>|&;]+)\s*<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/.exec(lines[i]);
		if (!match) continue;
		const [, file, tag] = match;
		const body: string[] = [];
		let j = i + 1;
		while (j < lines.length && lines[j].trim() !== tag) {
			body.push(lines[j]);
			j++;
		}
		if (j < lines.length) {
			bodies.set(canonicalPathForMatch(file), body.join("\n"));
			i = j;
		}
	}
	return bodies;
}

/** 把「不是 shell 语法」造成的噪音和真正的风险区分开。 */
function isUnverifiableNoise(finding: Finding): boolean {
	return (
		finding.kind === "unparsed" ||
		finding.reason.includes("cannot verify") ||
		finding.reason.includes("variable expansion") ||
		finding.reason.includes("too deep")
	);
}

function analyzeForkBomb(command: string): Finding | null {
	const dense = command.replace(/\s+/g, "");
	if (/:\(\)\{.*:\|:&.*\}/.test(dense) || dense.includes(":(){ :|:& };:")) {
		return { kind: "dangerous-command", severity: "dangerous", reason: "Fork bomb" };
	}
	return null;
}

/**
 * 分析一条 bash 命令。返回 null 表示允许。
 *
 * 引号不闭合时**仍逐段分析**：残缺引号后面的片段通常照常可解析
 * （`rm -rf /'` 的 `rm` 部分、`git reset --hard "` 都仍然命中）。
 * 只有「解析不了且没命中任何规则」才返回 `unparsed`，调用方据此降级为提示。
 */
/**
 * 把 heredoc 正文挖掉，只留命令行本身。
 * 正文是数据（python 源码、JSON、脚本内容），按 shell 逐行解析会造出成片误报：
 * `cat > x.py <<'PY' … PY` 里随便一行 `TMPH=$(mktemp -d)` 都会被当成命令。
 * 正文仍然会在「写入后立即执行」的路径里被单独分析。
 */
function stripHeredocs(command: string): string {
	const lines = command.split("\n");
	const out: string[] = [];
	for (let i = 0; i < lines.length; i++) {
		out.push(lines[i]);
		const match = /<<(-?)\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?/.exec(lines[i]);
		if (!match) continue;
		const allowTabs = match[1] === "-";
		const tag = match[2];
		const isEnd = (line: string) => (allowTabs ? line.replace(/^\t+/, "") === tag : line === tag);
		let j = i + 1;
		// 嵌套 heredoc（正文里出现同名的 <<'PY'）不能提前收尾，否则后半段会被当成命令
		while (j < lines.length && !isEnd(lines[j])) j++;
		if (j >= lines.length) continue; // 没闭合：按普通文本处理，别吞掉后面的命令
		out.push(""); // 正文占位，保持行结构
		i = j;        // 跳过正文与结束标记
	}
	return out.join("\n");
}

export function analyzeCommand(command: string, cwd: string, depth = 0): Finding | null {
	if (typeof command !== "string" || command.trim() === "") return null;

	const forkBomb = analyzeForkBomb(command);
	if (forkBomb) return forkBomb;

	const stripped = stripHeredocs(command);

	const { parts, separators, balanced } = splitCommands(stripped);

	const piped = analyzePipeToShell(parts, separators);
	if (piped) return piped;

	const writeThenRun = analyzeWriteThenRun(parts, command, cwd, depth);
	if (writeThenRun) return writeThenRun;

	const { literals: vars, tempVars } = scanAssignments(stripped);

	let effectiveCwd = cwd;
	for (const part of parts) {
		const finding = analyzeSegment(part, effectiveCwd, depth, vars, tempVars);
		if (finding) return finding;
		const moved = cdTarget(part, effectiveCwd);
		if (moved !== null) effectiveCwd = moved;
	}

	if (!balanced) {
		return { kind: "unparsed", severity: "notice", reason: "Command has unbalanced quotes; cannot verify it is safe" };
	}

	return null;
}
