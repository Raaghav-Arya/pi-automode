import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";
import {
	deterministicHardDeny,
	isRootHomeOrSystemPath,
	tempRootCandidates,
	PI_GLOBAL_SETTINGS,
	PI_LEGACY_GLOBAL_SETTINGS,
} from "../extensions/auto-mode.ts";

test("deterministic hard deny catches safety-control edits", () => {
	const cwd = "/tmp/project";
	assert.match(
		deterministicHardDeny("write", { path: ".pi/automode.local.json" }, cwd) ?? "",
		/safety-control/,
	);
	assert.match(
		deterministicHardDeny("bash", { command: "echo test >> ~/.zshrc" }, cwd) ?? "",
		/shell profile/,
	);
});

test("deterministic hard deny protects global Pi extensions and settings", () => {
	const agentDir = join(os.homedir(), ".pi/agent");
	for (const path of [
		join(agentDir, "extensions/auto-mode.ts"),
		join(agentDir, "extensions/pi-automode/config.json"),
		join(os.homedir(), ".PI/AGENT/EXTENSIONS/auto-mode.ts"),
		join(agentDir, "settings.json"),
		join(agentDir, "settings/providers.json"),
	]) {
		assert.match(
			deterministicHardDeny("write", { path }, "/tmp/project") ?? "",
			/safety-control/,
			path,
		);
	}
	assert.match(
		deterministicHardDeny(
			"edit",
			{ path: join(agentDir, "settings.json") },
			"/tmp/project",
		) ?? "",
		/safety-control/,
	);

	assert.equal(
		deterministicHardDeny(
			"write",
			{ path: "/tmp/project/src/app.ts" },
			"/tmp/project",
		),
		undefined,
	);
});

test("deterministic hard deny resolves symlinks to global Pi extensions", () => {
	const project = mkdtempSync(join(os.tmpdir(), "pi-automode-global-extension-link-"));
	try {
		const link = join(project, "linked-extensions");
		symlinkSync(join(os.homedir(), ".pi/agent/extensions"), link);
		assert.match(
			deterministicHardDeny(
				"write",
				{ path: join(link, "auto-mode.ts") },
				project,
			) ?? "",
			/safety-control/,
		);
	} finally {
		rmSync(project, { recursive: true, force: true });
	}
});
test("deterministic hard deny protects OMP auto-mode and permission artifacts", () => {
	const project = "/tmp/project";
	for (const path of [
		PI_GLOBAL_SETTINGS[0],
		PI_LEGACY_GLOBAL_SETTINGS,
		join(os.homedir(), ".omp/agent/extensions/auto-mode.ts"),
		join(os.homedir(), ".omp/agent/extensions/pi-permission-system/config.json"),
		join(project, ".omp/automode.local.json"),
		join(project, ".omp/extensions/my-auto-mode.ts"),
	]) {
		assert.match(
			deterministicHardDeny("write", { path }, project) ?? "",
			/safety-control/,
			path,
		);
	}
	// Extension source file
	const extSourcePath = fileURLToPath(new URL("../extensions/auto-mode/paths.ts", import.meta.url));
	assert.match(
		deterministicHardDeny("write", { path: extSourcePath }, project) ?? "",
		/safety-control/,
	);
	// Bash commands
	assert.match(
		deterministicHardDeny("bash", { command: "cp x ~/.omp/agent/automode.json" }, project) ?? "",
		/safety-control/,
	);
	assert.match(
		deterministicHardDeny("bash", { command: "tee .omp/extensions/auto-mode.ts" }, project) ?? "",
		/safety-control/,
	);
});

test("deterministic hard deny leaves ordinary OMP self-configuration alone", () => {
	const project = "/tmp/project";
	for (const path of [
		join(os.homedir(), ".omp/agent/config.yml"),
		join(os.homedir(), ".omp/agent/extensions/my-tool.ts"),
		join(os.homedir(), ".omp/agent/skills/x/SKILL.md"),
		join(project, ".omp/extensions/foo.ts"),
	]) {
		assert.equal(
			deterministicHardDeny("write", { path }, project),
			undefined,
			path,
		);
	}
	// Bash commands
	assert.equal(
		deterministicHardDeny("bash", { command: "cp ./foo.ts ~/.omp/agent/extensions/foo.ts" }, project),
		undefined,
	);
	assert.equal(
		deterministicHardDeny("bash", { command: "cat ~/.omp/agent/automode.json" }, project),
		undefined,
	);
});
/**
 * Run `body` in a child process whose HOME (and so os.homedir()) is `home` and
 * whose cwd is `root`. `body` sees `hardDeny(tool, input, cwd)`. Returns the JSON
 * value the body logs via `out(...)`. A child process is required because
 * HOME-derived constants and the extension source dir are fixed at module load,
 * so a static import cannot vary them (hence the runtime `import()` in the script).
 */
function runWithHome(home: string, root: string, body: string): unknown {
	const entry = pathToFileURL(join(root, "extensions/auto-mode.ts")).href;
	const script = `
		const { deterministicHardDeny } = await import(${JSON.stringify(entry)});
		const hardDeny = (tool, input, cwd = "/nonexistent-cwd") =>
			deterministicHardDeny(tool, input, cwd) ?? null;
		const out = (value) => process.stdout.write(JSON.stringify(value));
		${body}
	`;
	const result = spawnSync(
		process.execPath,
		["--import", "tsx", "--input-type=module", "--eval", script],
		{
			cwd: root,
			env: { ...process.env, HOME: home, USERPROFILE: home },
			encoding: "utf8",
		},
	);
	assert.equal(result.status, 0, result.stderr);
	return JSON.parse(result.stdout);
}

test("deterministic hard deny protects a stow-style symlinked OMP config by realpath", () => {
	// Isolated HOME: never touches the real ~/.omp.
	const home = mkdtempSync(join(os.tmpdir(), "stow-home-"));
	try {
		const target = join(home, "dotfiles/omp/automode.json");
		mkdirSync(join(home, "dotfiles/omp"), { recursive: true });
		mkdirSync(join(home, ".omp/agent"), { recursive: true });
		writeFileSync(target, "{}\n");
		symlinkSync(target, join(home, ".omp/agent/automode.json"));
		writeFileSync(join(home, "dotfiles/omp/other.json"), "{}\n");

		const result = runWithHome(
			home,
			process.cwd(),
			`out({
				realpath: hardDeny("write", { path: ${JSON.stringify(target)} }),
				viaLink: hardDeny("write", { path: ${JSON.stringify(join(home, ".omp/agent/automode.json"))} }),
				bashViaLink: hardDeny("bash", { command: "cp x ~/.omp/agent/automode.json" }),
				sibling: hardDeny("write", { path: ${JSON.stringify(join(home, "dotfiles/omp/other.json"))} }),
			})`,
		) as Record<string, string | null>;

		// `target` is outside .omp and is not named like a Pi rule, so only the
		// configured-config realpath rule can block it.
		assert.match(result.realpath ?? "", /safety-control/);
		assert.match(result.viaLink ?? "", /safety-control/);
		assert.match(result.bashViaLink ?? "", /safety-control/);
		assert.equal(result.sibling, null);
	} finally {
		rmSync(home, { recursive: true, force: true });
	}
});

test("deterministic hard deny protects the running extension's own source wherever installed", () => {
	// Copy the extension to a path without `/pi-automode/` so only the
	// extension-source rule can match.
	const root = mkdtempSync(join(os.tmpdir(), "ext-copy-"));
	try {
		cpSync(join(process.cwd(), "extensions"), join(root, "extensions"), { recursive: true });
		cpSync(join(process.cwd(), "package.json"), join(root, "package.json"));
		symlinkSync(join(process.cwd(), "node_modules"), join(root, "node_modules"));
		writeFileSync(join(root, "extensions/unrelated.ts"), "export {};\n");

		const result = runWithHome(
			os.homedir(),
			root,
			`out({
				source: hardDeny("write", { path: ${JSON.stringify(join(root, "extensions/auto-mode/classifier.ts"))} }),
				entry: hardDeny("edit", { path: ${JSON.stringify(join(root, "extensions/auto-mode.ts"))} }),
				unrelated: hardDeny("write", { path: ${JSON.stringify(join(root, "extensions/unrelated.ts"))} }),
			})`,
		) as Record<string, string | null>;

		assert.match(result.source ?? "", /safety-control/);
		assert.match(result.entry ?? "", /safety-control/);
		assert.equal(result.unrelated, null);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("deterministic hard deny handles case variants and .. traversal for OMP", () => {
	const project = "/tmp/project";
	
	// Case variants (macOS/Windows)
	assert.match(
		deterministicHardDeny("write", { path: join(os.homedir(), ".OMP/AGENT/AUTOMODE.JSON") }, project) ?? "",
		/safety-control/,
		"uppercase .OMP",
	);
	assert.match(
		deterministicHardDeny("write", { path: join(os.homedir(), ".Omp/Agent/Extensions/Auto-Mode.ts") }, project) ?? "",
		/safety-control/,
		"mixed case .Omp",
	);
	assert.match(
		deterministicHardDeny("write", { path: join(os.homedir(), ".omp/agent/extensions/Permission-System/config.json") }, project) ?? "",
		/safety-control/,
		"Permission-System dir",
	);
	
	// .. traversal into .omp
	assert.match(
		deterministicHardDeny("write", { path: join(project, "subdir/../.omp/agent/automode.json") }, project) ?? "",
		/safety-control/,
		".. traversal",
	);
	
	// Bash .. traversal
	assert.match(
		deterministicHardDeny("bash", { command: "cp x ../.omp/agent/automode.json" }, join(project, "subdir")) ?? "",
		/safety-control/,
		"bash .. traversal",
	);
	
	// Project .omp at depth
	assert.match(
		deterministicHardDeny("write", { path: join(project, "a/b/.omp/automode.local.json") }, project) ?? "",
		/safety-control/,
		"nested project .omp",
	);
	assert.match(
		deterministicHardDeny("write", { path: join(project, "a/b/.omp/extensions/auto-mode.ts") }, project) ?? "",
		/safety-control/,
		"nested project .omp/extensions",
	);
	
	// edit tool on protected paths
	assert.match(
		deterministicHardDeny("edit", { path: join(os.homedir(), ".omp/agent/automode.json") }, project) ?? "",
		/safety-control/,
		"edit tool on automode.json",
	);
	assert.match(
		deterministicHardDeny("edit", { path: join(os.homedir(), ".omp/agent/extensions/auto-mode.ts") }, project) ?? "",
		/safety-control/,
		"edit tool on auto-mode.ts",
	);
});

test("deterministic hard deny does not over-block permission-named files outside extension entry", () => {
	const project = "/tmp/project";
	
	// These should NOT be hard-denied (they're nested files, not extension entries)
	assert.equal(
		deterministicHardDeny("write", { path: join(os.homedir(), ".omp/agent/extensions/my-tool/permission.ts") }, project),
		undefined,
		"permission.ts nested file",
	);
	assert.equal(
		deterministicHardDeny("write", { path: join(os.homedir(), ".omp/agent/extensions/my-tool/permissions-helper.ts") }, project),
		undefined,
		"permissions-helper.ts nested file",
	);
	assert.equal(
		deterministicHardDeny("bash", { command: `node ${join(os.homedir(), ".omp/agent/extensions/my-tool/permissions-helper.js")}` }, project),
		undefined,
		"running extension with permission in name",
	);
	assert.equal(
		deterministicHardDeny("bash", { command: `sed -n 1p ${join(os.homedir(), ".omp/agent/extensions/foo/permission.ts")}` }, project),
		undefined,
		"read-only sed on permission-named file",
	);
	
	// But these ARE extension entries and should be blocked
	assert.match(
		deterministicHardDeny("write", { path: join(os.homedir(), ".omp/agent/extensions/permission-system/config.json") }, project) ?? "",
		/safety-control/,
		"permission-system entry",
	);
	assert.match(
		deterministicHardDeny("write", { path: join(os.homedir(), ".omp/agent/extensions/permissions/settings.json") }, project) ?? "",
		/safety-control/,
		"permissions entry",
	);
});
test("deterministic hard deny separates reading OMP auto-mode files from writing them", () => {
	const project = "/tmp/project";
	const config = join(os.homedir(), ".omp/agent/automode.json");
	const entry = join(os.homedir(), ".omp/agent/extensions/auto-mode.ts");

	// Reads (including cp/sed sources) are not deterministic hard-denies.
	for (const command of [
		`cat ${config}`,
		`sed -n 1,5p ${config}`,
		`cp ${entry} /tmp/entry-copy.ts`,
		`cp -a ${config} /tmp/automode-backup.json`,
	]) {
		assert.equal(deterministicHardDeny("bash", { command }, project), undefined, command);
	}

	// Writes are: cp destination, sed -i, mv, tee, rm.
	for (const command of [
		`cp /tmp/x ${config}`,
		`sed -i s/a/b/ ${config}`,
		`sed --in-place s/a/b/ ${config}`,
		`mv /tmp/x ${entry}`,
		`echo x | tee ${config}`,
		`rm ${entry}`,
	]) {
		assert.match(
			deterministicHardDeny("bash", { command }, project) ?? "",
			/safety-control/,
			command,
		);
	}
});

test("deterministic hard deny follows cd before resolving relative OMP targets", () => {
	const project = "/tmp/project";

	// A relative write target after `cd` lands in the OMP config directory.
	for (const command of [
		"cd ~/.omp/agent && echo '{}' > automode.json",
		"cd ~/.omp/agent && cp /tmp/x automode.json",
		"cd ~/.omp/agent; sed -i s/a/b/ automode.json",
		"(cd ~/.omp/agent; tee automode.json)",
		"cd -- ~/.omp/agent && cp /tmp/x automode.json",
		"cd ~/.omp/agent/extensions && cp /tmp/x auto-mode.ts",
		"cd .omp && rm automode.local.json",
	]) {
		assert.match(
			deterministicHardDeny("bash", { command }, project) ?? "",
			/safety-control/,
			command,
		);
	}

	// Reads, ordinary extensions, other directories, and unresolvable cd targets stay allowed.
	for (const command of [
		"cd ~/.omp/agent && cat automode.json",
		"cd ~/.omp/agent && cp automode.json /tmp/backup.json",
		"cd ~/.omp/agent/extensions && cp /tmp/x my-tool.ts",
		"cd /tmp && echo hi > out.txt",
		"cd $SOMEDIR && cp /tmp/x automode.json",
	]) {
		assert.equal(deterministicHardDeny("bash", { command }, project), undefined, command);
	}
});
test("deterministic hard deny catches OMP auto-mode paths inside inline interpreter scripts", () => {
	const project = "/tmp/project";
	for (const command of [
		`python3 -c 'open("/home/u/.omp/agent/automode.json","w").write("{}")'`,
		`node -e 'require("fs").writeFileSync(process.env.HOME+"/.omp/agent/automode.json","{}")'`,
		`perl -e 'open(F,">","/home/u/.omp/agent/extensions/auto-mode.ts")'`,
	]) {
		assert.match(
			deterministicHardDeny("bash", { command }, project) ?? "",
			/safety-control/,
			command,
		);
	}
	// An interpreter on an ordinary OMP extension is untouched.
	assert.equal(
		deterministicHardDeny(
			"bash",
			{ command: `node -e 'require("fs").writeFileSync("/home/u/.omp/agent/extensions/my-tool.ts","")'` },
			project,
		),
		undefined,
	);
});

test("deterministic hard deny sees OMP entries behind a directory symlink that drops .omp", () => {
	// Isolated HOME: the symlink target has no `.omp/` segment, so only the
	// lexical (as-addressed) path can identify the entry.
	const home = mkdtempSync(join(os.tmpdir(), "dirlink-home-"));
	try {
		mkdirSync(join(home, "dots/ext"), { recursive: true });
		mkdirSync(join(home, ".omp/agent"), { recursive: true });
		symlinkSync(join(home, "dots/ext"), join(home, ".omp/agent/extensions"));

		const result = runWithHome(
			home,
			process.cwd(),
			`out({
				entry: hardDeny("write", { path: ${JSON.stringify(join(home, ".omp/agent/extensions/auto-mode.ts"))} }),
				permEntry: hardDeny("write", { path: ${JSON.stringify(join(home, ".omp/agent/extensions/permission-system/c.json"))} }),
				bash: hardDeny("bash", { command: "cp x ~/.omp/agent/extensions/auto-mode.ts" }),
				ordinary: hardDeny("write", { path: ${JSON.stringify(join(home, ".omp/agent/extensions/my-tool.ts"))} }),
			})`,
		) as Record<string, string | null>;

		assert.match(result.entry ?? "", /safety-control/);
		assert.match(result.permEntry ?? "", /safety-control/);
		assert.match(result.bash ?? "", /safety-control/);
		assert.equal(result.ordinary, null);
	} finally {
		rmSync(home, { recursive: true, force: true });
	}
});

test("deterministic hard deny catches TLS weakening and authorized_keys writes", () => {
	assert.match(
		deterministicHardDeny("bash", { command: "git config --global http.sslVerify false" }, process.cwd()) ?? "",
		/TLS/,
	);
	assert.match(
		deterministicHardDeny("bash", { command: "cat key.pub >> ~/.ssh/authorized_keys" }, process.cwd()) ?? "",
		/authorized_keys/,
	);
});

test("shell parsing catches risky suffixes, redirects, and quoted HOME targets", () => {
	assert.match(
		deterministicHardDeny("bash", { command: "echo safe && git config --global http.sslVerify false" }, process.cwd()) ?? "",
		/TLS/,
	);
	assert.match(
		deterministicHardDeny("bash", { command: "printf test > ~/.zshrc" }, process.cwd()) ?? "",
		/shell profile/,
	);
	assert.match(
		deterministicHardDeny("bash", { command: 'echo key > "$HOME/.ssh/authorized_keys"' }, process.cwd()) ?? "",
		/authorized_keys/,
	);
	assert.match(
		deterministicHardDeny("bash", { command: "echo nope | tee .pi/automode.local.json" }, "/tmp/project") ?? "",
		/safety-control/,
	);
});

test("AST hard-deny checks inspect nested and background commands", () => {
	for (const command of [
		'echo "$(git config --global http.sslVerify false)"',
		"cat <(git config --global http.sslVerify false)",
		"echo safe & git config --global http.sslVerify false",
		"if test -n x; then git config --global http.sslVerify false; fi",
	]) {
		assert.match(
			deterministicHardDeny("bash", { command }, process.cwd()) ?? "",
			/TLS/,
			command,
		);
	}
});

test("AST hard-deny checks inspect literal shell and eval wrappers", () => {
	for (const command of [
		`bash -c 'rm -rf /'`,
		`sh -c 'rm -rf /'`,
		`eval 'rm -rf /'`,
	]) {
		assert.match(
			deterministicHardDeny("bash", { command }, process.cwd()) ?? "",
			/irreversible deletion/,
			command,
		);
	}
});

test("AST hard-deny checks inspect literal shells behind transparent dispatch wrappers", () => {
	for (const command of [
		`command bash -c 'rm -rf /'`,
		`command -p /bin/bash -c 'rm -rf /'`,
		`exec sh -c 'rm -rf /'`,
		`exec -a worker /bin/sh -c 'rm -rf /'`,
		`env bash -c 'rm -rf /'`,
		`env -i MODE=test /bin/bash -c 'rm -rf /'`,
	]) {
		assert.match(
			deterministicHardDeny("bash", { command }, process.cwd()) ?? "",
			/irreversible deletion/,
			command,
		);
	}
});

test("AST hard-deny checks inspect commands behind transparent dispatch wrappers", () => {
	for (const command of [
		"command rm -rf /",
		"command -p /bin/rm -rf /",
		"exec rm -rf /",
		"exec -a worker /bin/rm -rf /",
		"env rm -rf /",
		"env -- MODE=test rm -rf /",
		"env 1=x rm -rf /",
		"env -i MODE=test /bin/rm -rf /",
		"env MODE=test command rm -rf /",
	]) {
		assert.match(
			deterministicHardDeny("bash", { command }, process.cwd()) ?? "",
			/irreversible deletion/,
			command,
		);
	}
});

test("AST hard-deny parses rm options and operands around the option delimiter", () => {
	const cwd = mkdtempSync(join(os.tmpdir(), "pi-automode-rm-options-"));
	try {
		symlinkSync("/", join(cwd, "-root"));
		assert.match(
			deterministicHardDeny(
				"bash",
				{ command: "rm -rf -- -root/etc" },
				cwd,
			) ?? "",
			/irreversible deletion/,
		);
		assert.equal(
			deterministicHardDeny(
				"bash",
				{ command: "rm -- --recursive /" },
				cwd,
			),
			undefined,
		);
	} finally {
		rmSync(cwd, { recursive: true, force: true });
	}
});

test("AST hard-deny checks normalize absolute executable paths", () => {
	assert.match(
		deterministicHardDeny("bash", { command: "/bin/rm -rf /" }, process.cwd()) ?? "",
		/irreversible deletion/,
	);
	assert.match(
		deterministicHardDeny(
			"bash",
			{ command: "/usr/bin/git config --global http.sslVerify false" },
			process.cwd(),
		) ?? "",
		/TLS/,
	);
});

test("AST hard-deny checks protect recursive rm variants and system roots", () => {
	for (const command of [
		"rm -Rf /",
		"rm --recurs /",
		"rm -rf ~",
		"rm -rf /home",
		"rm -rf /proc",
		"rm -rf /root",
		"rm -rf /run",
		"rm -rf /System",
		"rm -rf /Library",
		"rm -rf /Users",
		"rm -rf /Users/another-user",
		"rm -rf ~root",
		`rm -rf ~root/"child"`,
	]) {
		assert.match(
			deterministicHardDeny("bash", { command }, process.cwd()) ?? "",
			/irreversible deletion/,
			command,
		);
	}
});

test("AST hard-deny checks exempt OS temp-directory subtrees", () => {
	// Reported false positive: `rm -rf /tmp/<dir>` hard-denied on macOS because
	// /tmp is a symlink to /private/tmp and /private matched as a system root.
	assert.equal(
		deterministicHardDeny(
			"bash",
			{ command: "rm -rf /tmp/automode-allow-test" },
			process.cwd(),
		),
		undefined,
	);

	// Deleting a temp directory created with mktemp/mkdtemp is routine cleanup.
	// Prefix avoids the separate "pi-automode" substring safety-control deny so
	// this test exercises only the temp-root logic.
	const created = mkdtempSync(join(os.tmpdir(), "automode-temp-subtree-"));
	try {
		assert.equal(
			deterministicHardDeny(
				"bash",
				{ command: `rm -rf ${created}` },
				process.cwd(),
			),
			undefined,
		);
	} finally {
		rmSync(created, { recursive: true, force: true });
	}

	// Compound form from the field report stays allowed end to end.
	assert.equal(
		deterministicHardDeny(
			"bash",
			{ command: "rm -rf /tmp/foolfighter-debug && mkdir /tmp/foolfighter-debug && docker cp c:/data/x.db /tmp/foolfighter-debug/x.db" },
			process.cwd(),
		),
		undefined,
	);
});

test(
	"AST hard-deny checks keep the OS temp roots themselves protected",
	{ skip: process.platform !== "darwin" },
	() => {
		for (const command of [
			"rm -rf /tmp",
			"rm -rf /private/tmp",
			"rm -rf /var/folders",
			"rm -rf /private/var/folders",
		]) {
			assert.match(
				deterministicHardDeny("bash", { command }, process.cwd()) ?? "",
				/irreversible deletion/,
				command,
			);
		}
	},
);

test("AST hard-deny checks leave literal tildes and application roots to review", () => {
	for (const command of [
		`rm -rf "~"`,
		"rm -rf \\~",
		`rm -rf ~"root"`,
		"rm -- /",
		"rm -rf /opt/app",
		"rm -rf /srv/app",
		"git push",
	]) {
		assert.equal(
			deterministicHardDeny("bash", { command }, process.cwd()),
			undefined,
			command,
		);
	}
});

test(
	"AST hard-deny checks canonicalize case aliases on case-insensitive macOS volumes",
	{ skip: process.platform !== "darwin" || !existsSync("/system") },
	() => {
		const commands = ["rm -rf /system", "rm -rf /library"];
		const lowerHome = os.homedir().toLowerCase();
		if (lowerHome !== os.homedir() && existsSync(lowerHome)) {
			commands.push(`rm -rf ${lowerHome}`);
		}
		for (const command of commands) {
			assert.match(
				deterministicHardDeny("bash", { command }, process.cwd()) ?? "",
				/irreversible deletion/,
				command,
			);
		}
	},
);

test("AST hard-deny checks fail closed on malformed Bash input", () => {
	assert.match(
		deterministicHardDeny("bash", { command: 'echo "unterminated' }, process.cwd()) ?? "",
		/could not be parsed safely/,
	);
});

test("AST hard-deny checks do not execute or inspect quoted command text", () => {
	for (const command of [
		`echo 'git config --global http.sslVerify false'`,
		`printf '%s' 'rm -rf /'`,
		"git push origin main",
	]) {
		assert.equal(
			deterministicHardDeny("bash", { command }, process.cwd()),
			undefined,
			command,
		);
	}
});

test("isRootHomeOrSystemPath exempts home subtree but keeps home root and system paths", () => {
	// Silverblue-style HOME under /var: the case PR #7 fixed. With a real
	// os.homedir() this subtree used to match `path.startsWith("/var/")` and
	// hard-deny routine `rm -rf ~/...`.
	const home = "/var/home/jdoe";
	const cases: Array<[string, boolean]> = [
		[home, true], // rm -rf ~ stays blocked
		[`${home}/projects/foo/build`, false], // the bug: was true before the fix
		["/var", true], // /var itself stays protected
		["/var/log", true], // sibling system path under /var stays protected
		["/var/lib/pkg", true],
		["/etc", true],
		["/usr/share/x", true],
		["/", true],
		["/opt/app", false], // not a tracked system root
	];
	for (const [path, expected] of cases) {
		assert.equal(isRootHomeOrSystemPath(path, home), expected, `path=${path}`);
	}

	// Standard HOME (/home/user): system roots still protected, subtree exempt.
	const stdHome = "/home/jdoe";
	assert.equal(isRootHomeOrSystemPath(stdHome, stdHome), true);
	assert.equal(isRootHomeOrSystemPath(`${stdHome}/src/pkg`, stdHome), false);
	assert.equal(isRootHomeOrSystemPath("/home", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/home/other-user", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/proc/1", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/root/.ssh", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/run/service", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/System/Library", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/Library/LaunchDaemons", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/Users", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/Users/another-user", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/etc/hosts", stdHome), true);
	assert.equal(isRootHomeOrSystemPath("/opt/app", stdHome), false);
	assert.equal(isRootHomeOrSystemPath("/srv/app", stdHome), false);
});

test("isRootHomeOrSystemPath exempts temp subtrees but keeps temp roots", () => {
	// Injectable candidates keep this platform-independent: callers pass
	// symlink-resolved policy paths (`/tmp` → `/private/tmp` on macOS) and
	// unresolved fallbacks alike, so both spellings must be listed.
	const home = "/home/jdoe";
	const temps = ["/tmp", "/private/tmp", "/var/folders/gn/T"];
	assert.equal(isRootHomeOrSystemPath("/tmp/project/sub", home, temps), false);
	assert.equal(
		isRootHomeOrSystemPath("/private/tmp/session", home, temps),
		false,
	);
	assert.equal(isRootHomeOrSystemPath("/var/folders/gn/T/x", home, temps), false);
	assert.equal(isRootHomeOrSystemPath("/tmp", home, temps), true); // root itself stays blocked
	assert.equal(isRootHomeOrSystemPath("/private/tmp", home, temps), true);
	assert.equal(isRootHomeOrSystemPath("/var/folders/gn/T", home, temps), true);
	assert.equal(isRootHomeOrSystemPath("/usr/local/lib", home, temps), true);
	assert.equal(isRootHomeOrSystemPath("/etc/hosts", home, temps), true);
});

test("isRootHomeOrSystemPath keeps exact protections ahead of temp candidates", () => {
	// Injected candidates must never defeat exact protections: the Silverblue
	// home root, `/`, system subtrees, and broader declared values all stay
	// protected no matter what callers pass as tempRoots.
	const home = "/var/home/jdoe";
	assert.equal(isRootHomeOrSystemPath(home, home, ["/var"]), true);
	assert.equal(isRootHomeOrSystemPath("/etc/nginx", "/Users/x", [""]), true);
	assert.equal(isRootHomeOrSystemPath("/", "/Users/x", [""]), true);
	assert.equal(
		isRootHomeOrSystemPath("/private/etc/ssl", "/Users/x", ["/private"]),
		true,
	);
	assert.equal(isRootHomeOrSystemPath("/usr/share/doc", "/Users/x", ["/usr"]), true);
});

test("tempRootCandidates rejects malformed, protected, and home-ancestor declarations", async () => {
	const previousTmpdir = process.env.TMPDIR;
	const setTmpdir = (value: string | undefined) => {
		if (value === undefined) delete process.env.TMPDIR;
		else process.env.TMPDIR = value;
	};
	try {
		// Distinct query strings give each check a pristine module instance, so
		// earlier suite calls cannot mask these through memoization.
		setTmpdir("/");
		const slashModule = await import(
			`../extensions/auto-mode/hard-deny.ts?tmp-root-slash`
		);
		assert.ok(
			!slashModule.tempRootCandidates().includes(""),
			slashModule.tempRootCandidates().join(","),
		);

		setTmpdir("/private");
		const privateModule = await import(
			`../extensions/auto-mode/hard-deny.ts?tmp-root-private`
		);
		assert.ok(
			!privateModule.tempRootCandidates().includes("/private"),
			privateModule.tempRootCandidates().join(","),
		);

		setTmpdir("/etc/cache");
		const cacheModule = await import(
			`../extensions/auto-mode/hard-deny.ts?tmp-root-cache`
		);
		const cacheRoots = [...cacheModule.tempRootCandidates()];
		assert.ok(cacheRoots.some((root) => root.endsWith("/etc/cache")));

		setTmpdir("/var");
		const varModule = await import(
			`../extensions/auto-mode/hard-deny.ts?tmp-root-var`
		);
		const varRoots = [...varModule.tempRootCandidates()];
		assert.ok(!varRoots.includes("/var"), varRoots.join(","));
		if (process.platform === "darwin") {
			assert.ok(!varRoots.includes("/private/var"), varRoots.join(","));
		}

		setTmpdir(join(os.homedir(), ".."));
		const ancestorModule = await import(
			`../extensions/auto-mode/hard-deny.ts?tmp-root-ancestor`
		);
		assert.ok(
			!ancestorModule.tempRootCandidates().includes(resolve(os.homedir(), "..")),
			ancestorModule.tempRootCandidates().join(","),
		);
	} finally {
		setTmpdir(previousTmpdir);
	}
});

test("tempRootCandidates recomputes when the effective tmpdir changes", () => {
	const previousTmpdir = process.env.TMPDIR;
	try {
		process.env.TMPDIR = "/etc/cache-first";
		const first = tempRootCandidates();
		process.env.TMPDIR = "/etc/cache-second";
		const second = tempRootCandidates();
		assert.ok(first.some((root) => root.endsWith("/cache-first")), first.join(","));
		assert.ok(second.some((root) => root.endsWith("/cache-second")));
		assert.ok(!second.some((root) => root.endsWith("/cache-first")));
	} finally {
		if (previousTmpdir === undefined) delete process.env.TMPDIR;
		else process.env.TMPDIR = previousTmpdir;
	}
});

test("AST hard-deny applies temp policy to find -delete roots", () => {
	assert.equal(
		deterministicHardDeny(
			"bash",
			{ command: "find /tmp/automode-find-subtree -delete" },
			process.cwd(),
		),
		undefined,
	);
	assert.match(
		deterministicHardDeny("bash", { command: "find /tmp -delete" }, process.cwd()) ?? "",
		/system-wide delete/,
	);
});

test("AST hard-deny checks find global options before system-wide delete roots", () => {
	for (const command of [
		"find -H /etc -delete",
		"find -L /etc -delete",
		"find -H -L /etc -delete",
		"find -P /Users -delete",
	]) {
		assert.match(
			deterministicHardDeny("bash", { command }, process.cwd()) ?? "",
			/system-wide delete/,
			command,
		);
	}
	assert.equal(
		deterministicHardDeny(
			"bash",
			{ command: "find -H /tmp/automode-find-subtree -delete" },
			process.cwd(),
		),
		undefined,
	);
});
