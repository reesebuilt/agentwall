import { existsSync } from "fs";
import { DEFAULT_CA_DIR, generateCa, inspectCa, probeOpenssl, resolveCaPaths } from "../proxy/mitm-ca";
import type { CaPaths } from "../proxy/mitm-ca";

/**
 * `agentwall intercept` - the operator lifecycle for the local TLS interception CA.
 *
 * Creating a CA is cheap and reversible; installing one into a trust store is neither. So the two
 * are separate subcommands with the consequence printed in between, rather than one `init --yes`
 * that leaves a host trusting a key the operator never consciously accepted. `init` writes files
 * in a directory. `trust` prints commands and runs none of them: the privileged step stays in the
 * operator's own shell where they can read it first.
 *
 * All of the judgement lives in ../proxy/mitm-ca, which owns the only code that touches the
 * private key. Nothing in this file reads that key. It is stat'd for its mode and never opened,
 * so no line of operator output, no --json payload, and no route that later imports this module
 * can serialise it by accident. The fingerprint is printed freely because it is public by
 * construction: it is a hash of the certificate, which is the half you are meant to hand out.
 *
 * `openssl` is a precondition here, in exactly the category root and Linux are preconditions for
 * `agentwall perimeter`. It is not an npm dependency, and it is not a shortcut: Node cannot issue
 * an X.509 certificate at all. `crypto.X509Certificate` has no static issuer and `crypto.Certificate`
 * is the legacy SPKAC helper. Spawning a system binary is what this codebase already does for
 * `nft` in the perimeter, `systemctl` in the dashboard route, and the wrapped server in the MCP
 * bridge, and it is what keeps interception at zero new dependencies.
 *
 * The intended order is `status`, `init`, `trust`, then `status` again to confirm. Only `init`
 * writes anything.
 */

const EXIT_OK = 0;
/** No CA, an unusable one, or a host that cannot mint. */
const EXIT_FAIL = 1;
/** Bad arguments. */
const EXIT_USAGE = 2;

const VALUE_FLAGS = ["ca-dir", "days"];

/**
 * The only mode the CA key may have, mirrored from mitm-ca so `status` can label the mode it
 * prints. The authoritative check, and the refusal that actually stops interception starting,
 * lives in `inspectCa`. This constant only decides whether a number gets a label beside it, so a
 * drift here mislabels one line of output rather than weakening a control.
 */
const CA_KEY_MODE = 0o600;

/** Filename used when copying into a system anchor directory. The `.crt` suffix is load-bearing. */
const TRUST_FILENAME = "agentwall-ca.crt";

const USAGE = `Usage: agentwall intercept <subcommand> [options]

Subcommands:
  init      Create the local CA. Refuses to overwrite an existing one.
  status    Report openssl, the CA, its fingerprint, expiry, and key permissions.
  trust     Print how to install the CA certificate, per runtime. Installs nothing itself.
  path      Print the absolute CA certificate path and nothing else.

Options:
  --ca-dir <path>   where the CA lives (env AGENTWALL_CA_DIR, default ${DEFAULT_CA_DIR})
  --days <n>        init only: CA lifetime in days (default 825)
  --json            trust only: emit the instructions as JSON for a scripted install

Exit codes: 0 ok, 1 no CA or an unusable one, 2 bad usage. \`status\` exits 0 only when openssl is
present, the CA exists, and it reports no problems, so a deployment script can gate on it without
parsing the output.

Interception is opt-in and OFF by default. A CA on disk changes nothing on its own: the proxy
decrypts only when \`interception.enabled\` is true in your config. Absent means off, deliberately,
because silently decrypting an operator's traffic is not a default a security tool earns.

\`openssl\` is a precondition, the same way root is a precondition for \`agentwall perimeter\`. It is
not an npm dependency. Without it on PATH, \`init\` and interception both refuse rather than
degrade.

Installing this CA into a trust store is the serious step, and it is not reversible by deleting a
config line. Any holder of the private key at <ca-dir>/ca.key can mint a certificate for any site
and this host will accept it as genuine. Keep the key at mode 0600 on a machine you control, and
remove the trust store entry when you are done.`;

/** An operator mistake, not a failure of the host. Reported with usage and exit 2. */
class UsageError extends Error {}

interface ParsedArgs {
  subcommand: string;
  flags: Record<string, string>;
  json: boolean;
}

interface InterceptOptions {
  /**
   * Resolved once, at the top, and passed down. Every subcommand then names the same directory,
   * and `inspectCa` is handed paths rather than re-running flag/env/default precedence, so a
   * printed path can never disagree with the file that was actually examined.
   */
  paths: CaPaths;
  /** Explicit `--days`, or null to take the CA lifetime mitm-ca chose. */
  days: number | null;
  json: boolean;
}

/**
 * One runtime and the lines that make it trust the CA.
 *
 * `commands` holds literal shell lines in order. A line starting with `#` is a shell comment, so
 * caveats can live in the array itself and the whole thing stays safe to paste into a terminal or
 * to feed to `sh`. That is why there is no separate `notes` field: the text output and the --json
 * output are rendered from this one structure and cannot drift apart, and a caveat that only
 * appeared in the human version would be missing from exactly the scripted installs that never
 * had a human read them.
 */
interface TrustInstruction {
  runtime: string;
  commands: string[];
}

export async function runInterceptCommand(argv: string[]): Promise<number> {
  // A bare `agentwall intercept` is somebody asking what this does, not a mistake, so it prints
  // usage and succeeds. An unknown subcommand is a mistake and exits 2 further down.
  if (argv.length === 0) {
    console.log(USAGE);
    return EXIT_OK;
  }

  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    return reportUsageError(err);
  }

  if (args.subcommand === "help" || args.subcommand === "--help" || args.subcommand === "-h") {
    console.log(USAGE);
    return EXIT_OK;
  }

  try {
    const options = resolveOptions(args);
    switch (args.subcommand) {
      case "init":
        return commandInit(options);
      case "status":
        return commandStatus(options);
      case "trust":
        return commandTrust(options);
      case "path":
        return commandPath(options);
      default:
        throw new UsageError(`unknown intercept subcommand "${args.subcommand}".`);
    }
  } catch (err) {
    return reportUsageError(err);
  }
}

/**
 * `init` - create the CA, then say plainly what was created.
 *
 * The refusal to overwrite is mitm-ca's, not this function's, and it is reported verbatim. An
 * operator who re-runs `init` is usually trying to fix something, and the reason overwriting is
 * refused (every leaf already minted stops verifying, and the old certificate stays installed in
 * trust stores as a key nobody can account for) is the sentence that stops them from reaching for
 * `rm -rf` on a directory a running proxy is using.
 *
 * The warning below is printed on success, every time, with no flag to suppress it. This is the
 * moment the operator has a site-impersonating key on disk, and it is the cheapest place to say
 * so while the fact is still new.
 */
function commandInit(options: InterceptOptions): number {
  const result = generateCa(options.paths.dir, options.days === null ? undefined : { days: options.days });
  if (!result.ok) {
    console.error(`Could not create the CA: ${result.reason}`);
    return EXIT_FAIL;
  }

  // The OBSERVED mode, not the intended one. Printing a hardcoded 0600 beside a key that a strange
  // umask or filesystem left wider would be the small version of the failure this whole feature is
  // built to avoid: a reassuring line that is not a measurement. If it is wrong, `status` and the
  // startup check will both refuse, and the operator should hear it here first.
  const created = inspectCa(result.paths);
  console.log(`Local interception CA created in ${result.paths.dir}`);
  console.log(`  certificate  ${result.paths.certPath}`);
  console.log(`  private key  ${result.paths.keyPath}  (mode ${formatKeyMode(created.keyMode)})`);
  console.log(`  fingerprint  sha256:${result.fingerprint}`);
  for (const problem of created.problems) console.error(`  PROBLEM: ${problem}`);
  console.log("");
  console.log("WARNING: that private key is not a per-site credential. Whoever holds it can mint a");
  console.log("certificate for ANY site, and every runtime you install this CA into will accept it:");
  console.log("your bank, your identity provider, your package registry. Keep it at mode 0600 on a");
  console.log("machine you control, do not copy it to a shared host, and do not commit it. AgentWall");
  console.log("never logs it, never writes it to an audit record, and never serves it over HTTP.");
  console.log("Interception refuses to start if its mode is ever wider than 0600.");
  console.log("");
  console.log("Nothing trusts this CA yet and interception is still off. Next:");
  console.log("  agentwall intercept trust");
  return EXIT_OK;
}

/**
 * `status` - everything knowable about the CA on disk, and an exit code a script can gate on.
 *
 * Exit 0 means openssl is present, the CA exists, and it has no problems. Anything else is exit 1,
 * including the cases that look survivable, because the caller is usually a deployment script
 * deciding whether to turn interception on. A control that is half-installed and reports success
 * is the failure this repo has already paid for twice: an nftables ruleset that never loaded
 * because `redirect` is a reserved keyword, and a gitleaks config that reported a clean tree
 * because it inherited no rules. Both looked fine from the outside.
 *
 * The field table goes to stdout and the problems go to stderr, so `status > report.txt` still
 * shows the operator what is wrong.
 */
function commandStatus(options: InterceptOptions): number {
  const openssl = probeOpenssl();
  const ca = inspectCa(options.paths);

  console.log(`openssl       ${openssl.present ? "present" : "MISSING"}  (${openssl.detail})`);
  console.log(`ca directory  ${options.paths.dir}`);
  console.log(`certificate   ${ca.present ? options.paths.certPath : "absent"}`);
  console.log(`fingerprint   ${ca.fingerprint === null ? "unavailable" : `sha256:${ca.fingerprint}`}`);
  console.log(`not after     ${ca.notAfter ?? "unknown"}${ca.expired ? "  (EXPIRED)" : ""}`);
  console.log(`key mode      ${formatKeyMode(ca.keyMode)}`);

  const usable = openssl.present && ca.present && ca.problems.length === 0;

  if (!usable) {
    console.error("");
    console.error("This CA cannot be used for interception:");
    if (!openssl.present) {
      console.error(`  - ${openssl.detail}. openssl is required to mint leaf certificates; Node cannot`);
      console.error("    issue X.509 itself. Install it, then re-run.");
    }
    for (const problem of ca.problems) console.error(`  - ${problem}`);
    if (!ca.present) console.error("  Create one with `agentwall intercept init`.");
    return EXIT_FAIL;
  }

  console.log("");
  console.log("The CA is usable. Note what that does and does not say: these are properties of the");
  console.log("files on disk. It is not a statement that anything trusts this CA, and it says nothing");
  console.log("about whether interception is enabled in your config. AgentWall can only ever verify");
  console.log("trust for its own Node process; it cannot see the trust store of a Python, Go, curl, or");
  console.log("containerised agent.");
  return EXIT_OK;
}

/**
 * `trust` - print the install steps, run none of them.
 *
 * Every command here needs root, and a tool that silently modifies a host trust store is the
 * thing an operator should be most suspicious of. Printing is also what makes the consequence
 * legible: the paragraph above the commands is the actual decision being made, and it is above
 * them rather than below because that is the order they will be read in.
 *
 * A CA with problems (a loose key mode, say) still prints and still exits 0. The certificate is
 * installable regardless, the operator is mid-setup, and the refusal that matters is the one
 * interception makes at start-up. Only a missing CA is a failure here, because then there is
 * genuinely nothing to install.
 */
function commandTrust(options: InterceptOptions): number {
  const certPath = options.paths.certPath;
  const ca = inspectCa(options.paths);
  if (!ca.present) {
    console.error(`Nothing to install: there is no CA certificate at ${certPath}.`);
    for (const problem of ca.problems) console.error(`  - ${problem}`);
    console.error("Create one first: `agentwall intercept init`.");
    return EXIT_FAIL;
  }

  // Ordered system store first, then the runtimes that override it: the distribution steps cover
  // the most callers, and the environment variables only make sense as exceptions to them.
  const instructions: TrustInstruction[] = [
    {
      runtime: "Debian/Ubuntu (system trust store)",
      commands: [
        `sudo cp ${certPath} /usr/local/share/ca-certificates/${TRUST_FILENAME}`,
        "sudo update-ca-certificates",
        "# The .crt extension is required: update-ca-certificates skips files with any other",
        "# suffix, silently, so a copy named ca.pem looks installed and is not.",
        "# To undo: remove that file and re-run update-ca-certificates --fresh.",
      ],
    },
    {
      runtime: "RHEL/Fedora (system trust store)",
      commands: [
        `sudo cp ${certPath} /etc/pki/ca-trust/source/anchors/${TRUST_FILENAME}`,
        "sudo update-ca-trust",
        "# To undo: remove that file and re-run update-ca-trust.",
      ],
    },
    {
      runtime: "Node",
      commands: [
        `export NODE_EXTRA_CA_CERTS=${certPath}`,
        "# Node reads NODE_EXTRA_CA_CERTS ONCE, at process startup. A process that is already",
        "# running will not pick this up no matter what you export into its shell afterwards:",
        "# restart it. This is the single most common reason interception appears not to work.",
        "# Set it even after the distribution steps above. Node ships its own bundled root store",
        "# and does not consult the system one by default.",
      ],
    },
    {
      runtime: "Python (requests, urllib3, stdlib ssl)",
      commands: [
        `export REQUESTS_CA_BUNDLE=${certPath}`,
        `export SSL_CERT_FILE=${certPath}`,
        "# requests verifies against certifi's own bundle and ignores the system store, so the",
        "# distribution steps above are not enough on their own. SSL_CERT_FILE covers stdlib ssl.",
        "# Both variables name a file that REPLACES the default bundle rather than adding to it,",
        "# so point them at a concatenation of this certificate and your existing roots if the",
        "# process also needs to reach hosts that are not being intercepted.",
      ],
    },
    {
      runtime: "Go",
      commands: [
        `export SSL_CERT_FILE=${certPath}`,
        "# Go reads the system store, so on Linux the distribution steps above usually cover it.",
        "# SSL_CERT_FILE is the override for a scratch container or a static binary with no store.",
        "# Go ignores it on macOS and Windows, which use the platform verifier instead.",
      ],
    },
  ];

  if (options.json) {
    console.log(
      JSON.stringify({ caCertPath: certPath, fingerprint: ca.fingerprint, instructions }, null, 2)
    );
    return EXIT_OK;
  }

  console.log("Installing this certificate is a trust decision, not a configuration change.");
  console.log("");
  console.log(`Once ${certPath} is in a trust store, any holder of the private key beside`);
  console.log("it can mint a certificate for any site and this host will accept it as genuine. That is");
  console.log("the whole mechanism by which interception works, and there is no narrower version of it.");
  console.log(`The key is ${options.paths.keyPath}, mode 0600. Install this only on a machine you`);
  console.log("control, and remove the trust store entry when you are done.");
  console.log("");
  console.log(`Check you installed the right certificate: sha256:${ca.fingerprint ?? "unavailable"}`);

  for (const instruction of instructions) {
    console.log("");
    console.log(`${instruction.runtime}:`);
    for (const command of instruction.commands) console.log(`  ${command}`);
  }

  if (ca.problems.length > 0) {
    console.error("");
    console.error("Fix these before enabling interception, which will refuse to start otherwise:");
    for (const problem of ca.problems) console.error(`  - ${problem}`);
  }

  console.log("");
  console.log("Two things installing trust will not fix:");
  console.log("  - Certificate-pinned clients still break, correctly. A client that checks for one");
  console.log("    specific certificate or key sees this CA's leaf instead and refuses. Exempt those");
  console.log("    hosts with `interception.bypassHosts`. It is an exact match after normalisation with");
  console.log("    no wildcards, the same rule the egress allowlist uses, because a second looser");
  console.log("    convention beside it would be a bypass waiting to happen.");
  console.log("  - A runtime that ships its own CA bundle ignores the system store entirely, which is");
  console.log("    why the per-runtime variables above are listed separately rather than as a fallback.");
  return EXIT_OK;
}

/**
 * `path` - the certificate path on stdout, alone, so `$(agentwall intercept path)` works.
 *
 * Nothing else may ever be printed on stdout by this subcommand. The whole point is substitution
 * into another command line, and one stray banner turns a path into an argument list.
 */
function commandPath(options: InterceptOptions): number {
  // existsSync rather than inspectCa: the question is "where is the certificate", not "is this CA
  // healthy". inspectCa spawns openssl to read the expiry, which would be a process per shell
  // expansion and a new way for a substitution to fail on a host that is otherwise fine.
  //
  // Only the certificate is checked, not the key. Installing trust needs the certificate alone,
  // and a host that only installs trust has no business holding the key.
  if (!existsSync(options.paths.certPath)) {
    console.error(`no CA certificate at ${options.paths.certPath}. Create one with \`agentwall intercept init\`.`);
    return EXIT_FAIL;
  }

  console.log(options.paths.certPath);
  return EXIT_OK;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [subcommand, ...rest] = argv;
  if (subcommand === undefined) throw new UsageError("intercept needs a subcommand.");

  const flags: Record<string, string> = {};
  let json = false;

  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];

    if (arg === "--json") {
      json = true;
      continue;
    }
    if (!arg.startsWith("--")) throw new UsageError(`unexpected argument "${arg}".`);

    const name = arg.slice(2);
    if (!VALUE_FLAGS.includes(name)) throw new UsageError(`unknown flag "${arg}".`);

    const value = rest[i + 1];
    if (value === undefined || value.startsWith("--")) throw new UsageError(`${arg} needs a value.`);
    flags[name] = value;
    i += 1;
  }

  return { subcommand, flags, json };
}

/**
 * Resolve the CA location and validate every flag, for every subcommand.
 *
 * `--days` is validated here rather than inside `init` so that `intercept status --days banana`
 * is an error too. A flag that is quietly ignored on four subcommands out of five teaches an
 * operator that it was accepted, and the one time they pass it to `init` expecting a rejection
 * they will not get one.
 */
function resolveOptions(args: ParsedArgs): InterceptOptions {
  const paths = resolveCaPaths(args.flags["ca-dir"]);
  const rawDays = args.flags["days"];

  let days: number | null = null;
  if (rawDays !== undefined) {
    const parsed = Number(rawDays);
    // Integer and positive, not merely numeric. openssl takes `-days 0` and issues a certificate
    // that expired the moment it was created, which is a confusing way to discover a typo.
    if (!Number.isInteger(parsed) || parsed <= 0) {
      throw new UsageError(`--days: expected a positive integer, got ${JSON.stringify(rawDays)}.`);
    }
    days = parsed;
  }

  return { paths, days, json: args.json };
}

/** Render the key mode the way chmod takes it, labelled against the one mode that is acceptable. */
function formatKeyMode(mode: number | null): string {
  if (mode === null) return "unknown (no key file)";
  const octal = `0${mode.toString(8).padStart(3, "0")}`;
  // Same predicate inspectCa uses: any bit outside owner read/write. Narrower than 0600 is fine.
  return (mode & ~CA_KEY_MODE) === 0 ? octal : `${octal}  (WIDER THAN 0600)`;
}

function reportUsageError(err: unknown): number {
  console.error(err instanceof Error ? err.message : String(err));
  console.error("");
  console.error(USAGE);
  return EXIT_USAGE;
}
