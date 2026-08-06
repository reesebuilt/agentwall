//! Findings, layers, and the two output shapes.
//!
//! The three layers are never collapsed into one verdict. `docs/audit-format.md` opens with the
//! reason: the evidence "supports three different claims that fail independently, and collapsing
//! them into one verdict would hide which one an operator actually has."
//!
//! Problem CODES here are this implementation's own interface, not the format's. The document is
//! explicit that "the wording of any diagnostic message" is not part of the contract and that
//! stable code names are "that implementation's interface, not part of this format". They are
//! deliberately NOT copied from the Go verifier's names: if the third implementation reported
//! identical codes it would suggest a shared lineage the whole exercise is meant to avoid. What
//! the harness compares across implementations is the verdict and the counters.

use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub struct Problem {
    pub code: &'static str,
    pub text: String,
    /// Whether this finding fails its layer. A torn final line and a declared chain gap are
    /// reported without failing anything; a hash mismatch fails.
    pub fatal: bool,
}

impl Problem {
    pub fn fatal(code: &'static str, text: impl Into<String>) -> Self {
        Problem {
            code,
            text: text.into(),
            fatal: true,
        }
    }

    pub fn note(code: &'static str, text: impl Into<String>) -> Self {
        Problem {
            code,
            text: text.into(),
            fatal: false,
        }
    }

    pub fn rendered(&self) -> String {
        format!("{}: {}", self.code, self.text)
    }
}

/// A hostile file with a million broken lines must not produce a million-line report. The tail
/// is summarized instead: a verifier whose output an attacker can inflate without bound is
/// itself a denial of service.
const PROBLEM_CAP: usize = 100;

#[derive(Debug, Clone)]
pub struct Layer {
    pub name: &'static str,
    pub detail: String,
    pub problems: Vec<Problem>,
}

impl Layer {
    pub fn new(name: &'static str, detail: String, mut problems: Vec<Problem>) -> Self {
        if problems.len() > PROBLEM_CAP {
            let dropped = problems.len() - PROBLEM_CAP;
            let any_fatal_dropped = problems[PROBLEM_CAP..].iter().any(|p| p.fatal);
            problems.truncate(PROBLEM_CAP);
            problems.push(Problem {
                code: "problems-truncated",
                text: format!("{dropped} further finding(s) not shown"),
                fatal: any_fatal_dropped,
            });
        }
        Layer {
            name,
            detail,
            problems,
        }
    }

    pub fn ok(&self) -> bool {
        !self.problems.iter().any(|p| p.fatal)
    }
}

pub struct Report {
    pub layers: Vec<Layer>,
    pub pending: usize,
    pub confirmed: usize,
    pub failed: usize,
    /// Human-only sentence about what an unpinned signature does and does not establish.
    pub note: Option<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.layers.iter().all(|l| l.ok())
    }

    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(1024);
        s.push_str("{\n");
        let _ = writeln!(s, "  \"ok\": {},", self.ok());
        s.push_str("  \"layers\": [\n");
        for (i, layer) in self.layers.iter().enumerate() {
            s.push_str("    {\n");
            let _ = writeln!(s, "      \"name\": {},", quote(layer.name));
            let _ = writeln!(s, "      \"ok\": {},", layer.ok());
            let _ = writeln!(s, "      \"detail\": {},", quote(&layer.detail));
            if layer.problems.is_empty() {
                s.push_str("      \"problems\": []\n");
            } else {
                s.push_str("      \"problems\": [\n");
                for (j, p) in layer.problems.iter().enumerate() {
                    let _ = write!(s, "        {}", quote(&p.rendered()));
                    s.push_str(if j + 1 == layer.problems.len() {
                        "\n"
                    } else {
                        ",\n"
                    });
                }
                s.push_str("      ]\n");
            }
            s.push_str(if i + 1 == self.layers.len() {
                "    }\n"
            } else {
                "    },\n"
            });
        }
        s.push_str("  ],\n");
        let _ = writeln!(s, "  \"pending\": {},", self.pending);
        let _ = writeln!(s, "  \"confirmed\": {},", self.confirmed);
        let _ = writeln!(s, "  \"failed\": {},", self.failed);
        s.push_str("  \"verifier\": {\n");
        let _ = writeln!(s, "    \"name\": {},", quote(crate::VERIFIER_NAME));
        let _ = writeln!(s, "    \"version\": {},", quote(crate::VERIFIER_VERSION));
        let _ = writeln!(s, "    \"language\": {},", quote("rust"));
        let _ = writeln!(s, "    \"canon\": {}", quote("cu1"));
        s.push_str("  }\n}\n");
        s
    }

    pub fn to_human(&self) -> String {
        let mut s = String::new();
        for layer in &self.layers {
            let _ = writeln!(
                s,
                "{:<9} {}   {}",
                layer.name,
                if layer.ok() { "PASS" } else { "FAIL" },
                layer.detail
            );
        }
        let _ = writeln!(
            s,
            "\nanchors   {} confirmed, {} pending, {} failed",
            self.confirmed, self.pending, self.failed
        );
        for layer in &self.layers {
            if layer.problems.is_empty() {
                continue;
            }
            let _ = writeln!(s, "\n{}:", layer.name);
            for p in &layer.problems {
                let _ = writeln!(
                    s,
                    "  {} {}",
                    if p.fatal { "[fail]" } else { "[note]" },
                    p.rendered()
                );
            }
        }
        if let Some(note) = &self.note {
            let _ = writeln!(s, "\n{note}");
        }
        s
    }
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_layer_fails_only_on_a_fatal_finding() {
        let l = Layer::new("chained", "x".into(), vec![Problem::note("torn-tail", "t")]);
        assert!(l.ok());
        let l = Layer::new(
            "chained",
            "x".into(),
            vec![Problem::fatal("hash-broken", "t")],
        );
        assert!(!l.ok());
    }

    #[test]
    fn truncation_keeps_the_fatality_of_what_it_hid() {
        let mut problems: Vec<Problem> = (0..PROBLEM_CAP)
            .map(|_| Problem::note("noise", "n"))
            .collect();
        problems.push(Problem::fatal("hidden", "h"));
        let l = Layer::new("chained", "x".into(), problems);
        assert_eq!(l.problems.len(), PROBLEM_CAP + 1);
        assert!(
            !l.ok(),
            "a fatal finding past the cap must still fail the layer"
        );
    }

    #[test]
    fn json_escapes_hostile_text() {
        let l = Layer::new(
            "chained",
            "d".into(),
            vec![Problem::fatal("x", "he said \"hi\"\\ and\nnewline")],
        );
        let r = Report {
            layers: vec![l],
            pending: 0,
            confirmed: 0,
            failed: 0,
            note: None,
        };
        let json = r.to_json();
        assert!(json.contains(r#"\"hi\""#));
        assert!(json.contains(r"\\"));
        assert!(json.contains(r"\n"));
        assert!(!json.contains("\nnewline"));
    }
}
