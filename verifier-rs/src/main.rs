//! CLI for the Rust verifier.
//!
//! The flag surface and the exit codes match the bundled Go verifier so one harness can drive
//! every implementation with the same arguments: exit 0 when all three layers pass, 1 when any
//! layer fails, 2 for a usage or IO error, which is not a verdict about evidence.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use agentwall_verify_rs::{verify, Options, VERIFIER_NAME, VERIFIER_VERSION};

const USAGE: &str = "\
agentwall-verify (rust) - verify Agentwall audit evidence offline

Usage:
  agentwall-verify --audit <path> [flags]

Flags:
  --audit <path>        path to the audit JSONL file (required)
  --manifest <path>     rotation manifest (default segments.jsonl beside audit)
  --anchors <path>      anchor log (default anchors.jsonl beside audit)
  --proofs <dir>        directory of OpenTimestamps proof files (default proofs/ beside audit)
  --pubkey <base64>     base64 DER SPKI public key to pin checkpoints to
  --pubkey-file <path>  file holding that key
  --json                emit JSON instead of human-readable output
  --version             print version and exit
  --help                print this text

Exit codes:
  0  every layer passed
  1  at least one layer failed
  2  the arguments or the files could not be used, which is not a verdict
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args);
    ExitCode::from(code)
}

struct Args {
    audit: Option<PathBuf>,
    manifest: Option<PathBuf>,
    anchors: Option<PathBuf>,
    proofs: Option<PathBuf>,
    pubkey: Option<String>,
    pubkey_file: Option<PathBuf>,
    json: bool,
    version: bool,
    help: bool,
}

fn usage_error(message: &str) -> u8 {
    let mut err = std::io::stderr();
    let _ = writeln!(err, "error: {message}");
    let _ = write!(err, "{USAGE}");
    2
}

fn run(argv: &[String]) -> u8 {
    let mut args = Args {
        audit: None,
        manifest: None,
        anchors: None,
        proofs: None,
        pubkey: None,
        pubkey_file: None,
        json: false,
        version: false,
        help: false,
    };

    let mut i = 0;
    while i < argv.len() {
        let raw = argv[i].as_str();
        let trimmed = raw
            .strip_prefix("--")
            .or_else(|| raw.strip_prefix('-'))
            .unwrap_or("");
        if trimmed.is_empty() {
            return usage_error(&format!("unexpected argument {raw:?}"));
        }
        let (name, inline) = match trimmed.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (trimmed, None),
        };

        // Value-taking flags read the next argument when no `=value` was attached.
        let take_value = |i: &mut usize| -> Option<String> {
            if let Some(v) = inline.clone() {
                return Some(v);
            }
            *i += 1;
            argv.get(*i).cloned()
        };

        match name {
            "json" => args.json = true,
            "version" => args.version = true,
            "help" | "h" => args.help = true,
            "audit" => match take_value(&mut i) {
                Some(v) => args.audit = Some(PathBuf::from(v)),
                None => return usage_error("--audit needs a path"),
            },
            "manifest" => match take_value(&mut i) {
                Some(v) => args.manifest = Some(PathBuf::from(v)),
                None => return usage_error("--manifest needs a path"),
            },
            "anchors" => match take_value(&mut i) {
                Some(v) => args.anchors = Some(PathBuf::from(v)),
                None => return usage_error("--anchors needs a path"),
            },
            "proofs" => match take_value(&mut i) {
                Some(v) => args.proofs = Some(PathBuf::from(v)),
                None => return usage_error("--proofs needs a directory"),
            },
            "pubkey" => match take_value(&mut i) {
                Some(v) => args.pubkey = Some(v),
                None => return usage_error("--pubkey needs a base64 key"),
            },
            "pubkey-file" => match take_value(&mut i) {
                Some(v) => args.pubkey_file = Some(PathBuf::from(v)),
                None => return usage_error("--pubkey-file needs a path"),
            },
            other => return usage_error(&format!("unknown flag --{other}")),
        }
        i += 1;
    }

    if args.help {
        print!("{USAGE}");
        return 0;
    }
    if args.version {
        println!("{VERIFIER_NAME} {VERIFIER_VERSION}");
        return 0;
    }

    let Some(audit) = args.audit else {
        return usage_error("--audit is required");
    };
    if args.pubkey.is_some() && args.pubkey_file.is_some() {
        return usage_error("pass at most one of --pubkey or --pubkey-file");
    }
    if !audit.is_file() {
        return usage_error(&format!("audit file {} not found", audit.display()));
    }

    let pin = match (&args.pubkey, &args.pubkey_file) {
        (Some(k), _) => Some(k.trim().to_string()),
        (None, Some(path)) => match std::fs::read_to_string(path) {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                if trimmed.is_empty() {
                    return usage_error(&format!("{} holds no key", path.display()));
                }
                Some(trimmed)
            }
            Err(e) => return usage_error(&format!("cannot read {}: {e}", path.display())),
        },
        (None, None) => None,
    };

    let opts = Options::with_defaults(audit, args.manifest, args.anchors, args.proofs, pin);
    let report = verify(&opts);

    let out = if args.json {
        report.to_json()
    } else {
        report.to_human()
    };
    print!("{out}");
    let _ = std::io::stdout().flush();

    if report.ok() {
        0
    } else {
        1
    }
}
