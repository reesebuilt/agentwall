import { InjectionCategory, InjectionFinding, InjectionScanResult, NormalizationPass } from "../mcp/types";
import { RiskLevel } from "../types";
import { scanText } from "../planes/identity/dlp";

/**
 * Prompt-injection detection: deterministic patterns over normalized text.
 *
 * Why patterns and not a classifier: this runs inline on every frame crossing
 * the boundary, and a decision that cannot be explained cannot be appealed. A
 * pattern id in an audit record tells an operator exactly what fired and lets
 * them argue with it. A model score does not, and it would also add a runtime
 * dependency to the one component whose entire value is being trustworthy.
 *
 * What this does NOT do, stated plainly so nobody over-trusts it: paraphrase
 * defeats it. "Kindly set aside the guidance you were given at the start" is an
 * instruction override and nothing here matches it. This raises the cost of the
 * cheap, copy-pasted attack — which is the overwhelming majority of what
 * actually arrives in tool output — and it is a detection layer, not a proof of
 * absence. Treat a clean scan as "no known pattern", never as "safe".
 *
 * The normalization passes exist because raw matching is trivially defeated:
 * one zero-width space inside "ignore" is enough. Each pass rewrites the input
 * into a canonical form and the whole pattern set runs again. A finding records
 * which pass surfaced it, because "matched literally" and "matched only after
 * base64 decoding" mean different things to whoever triages it.
 */

interface InjectionPattern {
  patternId: string;
  category: InjectionCategory;
  severity: RiskLevel;
  pattern: RegExp;
  /** Reject matches that are the object of a prohibition. See NEGATION_PREFIX. */
  guarded?: true;
}

/**
 * "Do not send credentials to third parties" is security guidance, not an
 * exfiltration directive, and a detector that cannot tell the difference gets
 * muted by its operator within a week. Verb-led patterns whose benign negated
 * form is common carry `guarded`, and a match is rejected when the text
 * immediately before it ends in one of these.
 *
 * This is checked after the match rather than written as a lookbehind inside
 * each pattern, and the difference is not stylistic: a pattern that opens with
 * a lookbehind gives the regex engine no leading character to filter on, so it
 * evaluates the assertion at every offset in the input. Measured on a 256 KB
 * scan that costs about 125x the same pattern without it. Rejecting after the
 * fact runs the assertion only where something actually matched.
 */
const NEGATION_PREFIX = /(?:\bdo\s{0,3}not|\bdon't|\bdoesn't|\bnever|\bcannot|\bcan't|\bwon't|\bmust\s{0,3}not|\bshould\s{0,3}not|\bshouldn't|\bavoid|\brefuse\s{0,3}to|\brefrain\s{0,3}from|\bnot)\s{0,3}$/i;

/** Characters of preceding text the negation check looks at; the longest phrase above fits in it. */
const NEGATION_LOOKBACK = 24;

/**
 * One character of filler between two anchor words, constrained to stay inside
 * a sentence.
 *
 * A plain `[^\n]` gap would let a verb in one sentence pair with a URL in the
 * next ("send the draft. The changelog links to https://..."), which is a false
 * positive with an obvious cause. Excluding the period outright is worse in the
 * other direction: it breaks on the payloads that matter most, because ".env",
 * "id_rsa.pub", and "evil.example" all carry dots. So a period is permitted
 * only when it is followed by a non-space, which is what separates a dot inside
 * a token from a dot ending a clause. Every use is lazy and length-capped.
 */
const SENTENCE_GAP = String.raw`(?:[^.\n]|\.(?=\S))`;

/**
 * The pattern pack.
 *
 * Severity is assigned by what the instruction accomplishes if it lands, not by
 * how confident the regex is. A directive that moves credentials off the host
 * or executes a command is critical because there is no recovery from a
 * successful one. Role manipulation is medium: it is a real signal and a real
 * precursor, but on its own it changes tone, not state.
 *
 * Word gaps are `\s*` rather than `\s+` throughout. The whitespace pass removes
 * every space, so "ignoreallprevious" has to match the same pattern that
 * matches "ignore all previous". Every pattern is anchored with `\b` for the
 * same reason: without it, whitespace removal would join innocent neighbours
 * ("React as a framework" -> "Reactasaframework") into matches.
 *
 * No pattern nests an unbounded quantifier inside another, and every gap
 * between anchor words is lazy and length-capped (`SENTENCE_GAP{0,60}?` or
 * `[^.\n]{0,40}?`), so a hostile input cannot turn a scan into a denial of
 * service against the thing doing the scanning. A 256 KB adversarial payload
 * scans in well under a second.
 */
const INJECTION_PATTERNS: InjectionPattern[] = [
  // --- instruction_override -------------------------------------------------
  {
    patternId: "inj.instruction_override.ignore_previous",
    category: "instruction_override",
    severity: "high",
    // The trailing noun is optional but not free: without it the match must be
    // followed by punctuation, end of input, or a pivot word. That keeps the
    // letter-spaced "i g n o r e   a l l   p r e v i o u s" and the common
    // "ignore the above and instead ..." while leaving "you can safely ignore
    // previous warnings" alone.
    pattern: /\bignore\s*(?:all\s*|any\s*)?(?:of\s*)?(?:the\s*|these\s*|those\s*|your\s*|my\s*)?(?:previous|prior|above|preceding|earlier|foregoing|former)(?:\s*(?:instructions?|prompts?|directives?|rules?|messages?|commands?|guidelines?|context|input|statements?)\b|(?=\s*(?:$|[.,;:!?\n)\]"'`]|and\b|then\b|instead\b|but\b)))/i,
  },
  {
    patternId: "inj.instruction_override.disregard_instructions",
    category: "instruction_override",
    severity: "high",
    guarded: true,
    pattern: /\b(?:disregard|discard|dismiss|overlook|set\s*aside|throw\s*out)\s*(?:all\s*|any\s*)?(?:of\s*)?(?:the\s*|your\s*|these\s*)?(?:previous\s*|prior\s*|above\s*|preceding\s*|earlier\s*|system\s*|original\s*|initial\s*|existing\s*)?(?:instructions?|prompts?|directives?|rules?|guidelines?|constraints?|restrictions?)\b/i,
  },
  {
    patternId: "inj.instruction_override.forget_instructions",
    category: "instruction_override",
    severity: "high",
    // Guarded: "don't forget the instructions in the README" is a reminder.
    guarded: true,
    pattern: /\bforget\s*(?:about\s*)?(?:everything|all|what|anything)?\s*(?:you\s*(?:were\s*told|know|learned|read)|(?:the\s*|your\s*)?(?:previous\s*|prior\s*|above\s*|earlier\s*|original\s*|system\s*)?(?:instructions?|prompts?|rules?|directives?|guidelines?))\b/i,
  },
  {
    patternId: "inj.instruction_override.new_instructions",
    category: "instruction_override",
    severity: "high",
    pattern: /\b(?:new|updated|revised|additional|real|actual|true|following)\s*(?:and\s*final\s*)?(?:system\s*)?(?:instructions?|prompts?|directives?)\s*(?::|follow\b|below\b|begin\b|start\s*(?:here|now)\b|are\s*as\s*follows\b)/i,
  },
  {
    patternId: "inj.instruction_override.system_prompt_block",
    category: "instruction_override",
    severity: "high",
    // A colon is required: prose that merely names the concept ("system prompt
    // storage") is discussion, an inline block that opens one is an injection.
    pattern: /\bsystem\s*(?:prompt|message|instructions?)\s*:/i,
  },
  {
    patternId: "inj.instruction_override.override_directive",
    category: "instruction_override",
    severity: "high",
    pattern: /\boverride\s*(?:(?:all|any|the|your|previous|prior|existing|current)\s*){0,4}(?:instructions?|prompts?|rules?|polic(?:y|ies)|guidelines?|guardrails?|restrictions?|safety|settings|configuration)\b/i,
  },
  {
    patternId: "inj.instruction_override.disable_safety",
    category: "instruction_override",
    severity: "high",
    pattern: /\b(?:ignore|bypass|disable|turn\s*off|circumvent|override|lift|suspend|remove)\s*(?:all\s*|any\s*|the\s*|your\s*)?(?:(?:safety|security|content|moderation|ethical|alignment)\s*(?:polic(?:y|ies)|filters?|guidelines?|rules?|restrictions?|guardrails?|checks?|constraints?|controls?)|guardrails?|safety\s*protocols?|content\s*filters?)\b/i,
  },
  {
    patternId: "inj.instruction_override.stop_following",
    category: "instruction_override",
    severity: "high",
    pattern: /\b(?:do\s*not|don't|never|stop)\s*(?:follow(?:ing)?|obey(?:ing)?|adher(?:e|ing)\s*to|comply(?:ing)?\s*with)\s*(?:the\s*|your\s*|any\s*|all\s*)?(?:previous\s*|prior\s*|above\s*|earlier\s*|original\s*|system\s*|initial\s*)?(?:instructions?|prompts?|rules?|guidelines?|directives?|polic(?:y|ies))\b/i,
  },
  {
    patternId: "inj.instruction_override.supersedes_prior",
    category: "instruction_override",
    severity: "high",
    pattern: /\b(?:this|these|the\s*following|below)\s*(?:new\s*)?(?:instructions?|prompts?|messages?|directives?|rules?)\s*(?:supersede[sd]?|override[sd]?|take[s]?\s*precedence|replace[sd]?|invalidate[sd]?)\b/i,
  },
  {
    patternId: "inj.instruction_override.everything_above_void",
    category: "instruction_override",
    severity: "high",
    pattern: /\b(?:everything|anything|all)\s*(?:written\s*|said\s*|stated\s*|mentioned\s*)?(?:above|before\s*(?:this|the\s*\w{1,12})|prior\s*to\s*this)\s*(?:is|was|should\s*be|must\s*be)?\s*(?:a\s*)?(?:ignored?|irrelevant|false|outdated|obsolete|void|wrong|a\s*test)\b/i,
  },

  // --- exfiltration_directive ----------------------------------------------
  {
    patternId: "inj.exfiltration_directive.send_to_url",
    category: "exfiltration_directive",
    severity: "critical",
    // The destination preposition is required. Without it "send a summary of
    // https://example.com/docs" — a normal request — would fire.
    guarded: true,
    pattern: new RegExp(
      String.raw`\b(?:send|post|upload|transmit|exfiltrate|forward|deliver|submit|push|leak|copy)\b` +
        `${SENTENCE_GAP}{0,60}?` +
        String.raw`\b(?:to|at|via|toward)\s*(?:the\s*)?(?:url\s*|endpoint\s*|webhook\s*)?https?:\/\/`,
      "i",
    ),
  },
  {
    patternId: "inj.exfiltration_directive.send_to_email",
    category: "exfiltration_directive",
    severity: "critical",
    guarded: true,
    pattern: new RegExp(
      String.raw`\b(?:send|email|e-mail|mail|forward|cc|bcc|deliver|report)\b` +
        `${SENTENCE_GAP}{0,60}?` +
        String.raw`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`,
      "i",
    ),
  },
  {
    patternId: "inj.exfiltration_directive.credential_material",
    category: "exfiltration_directive",
    severity: "critical",
    // Two shapes of target: the English noun ("api keys", "credentials") and
    // the environment-variable spelling (AWS_SECRET_ACCESS_KEY). The variable
    // branch demands a credential word in the compound, so "primary_key" and
    // "sort_key" do not qualify.
    guarded: true,
    pattern: new RegExp(
      String.raw`\b(?:send|post|upload|print|output|dump|reveal|leak|expose|share|return|include|email|echo|show|display|exfiltrate|transmit)\b` +
        `${SENTENCE_GAP}{0,50}?` +
        // The word boundary sits inside the alternation rather than in front of
        // it: a leading `\b` would make the ".env" branch unreachable, because
        // the position before a dot preceded by a space is not a boundary.
        String.raw`(?:\$\{?)?(?:\b(?:env(?:ironment)?\s*(?:vars?|variables?)|api\s*keys?|secret\s*keys?|access\s*tokens?|auth\s*tokens?|bearer\s*tokens?|credentials?|passwords?|private\s*keys?|ssh\s*keys?|[A-Za-z][A-Za-z0-9]*_(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH_?TOKEN)(?:_[A-Za-z0-9]+)*)|\.env)\b`,
      "i",
    ),
  },
  {
    patternId: "inj.exfiltration_directive.reveal_system_prompt",
    category: "exfiltration_directive",
    severity: "high",
    pattern: /\b(?:print|show|reveal|repeat|display|output|disclose|dump|list|echo|tell\s*me|summar(?:ise|ize)|give\s*me|what\s*(?:is|are))\b[^.\n]{0,40}?\b(?:your\s*|the\s*|its\s*|full\s*|entire\s*|initial\s*|original\s*|exact\s*|verbatim\s*|hidden\s*|complete\s*){0,3}(?:system\s*(?:prompt|message|instructions?)|initial\s*(?:prompt|instructions?)|original\s*(?:prompt|instructions?)|hidden\s*(?:prompt|instructions?|rules?)|prompt\s*template)\b/i,
  },
  {
    patternId: "inj.exfiltration_directive.reveal_instructions",
    category: "exfiltration_directive",
    severity: "high",
    pattern: /\b(?:reveal|repeat|print|show|disclose|output|recite|tell\s*me|list)\b[^.\n]{0,30}?\byour\s*(?:full\s*|complete\s*|exact\s*|entire\s*|original\s*){0,2}(?:instructions?|rules?|guidelines?|directives?|configuration|constraints?|prompt)\b/i,
  },
  {
    patternId: "inj.exfiltration_directive.share_conversation",
    category: "exfiltration_directive",
    severity: "high",
    guarded: true,
    pattern: new RegExp(
      String.raw`\b(?:send|share|forward|post|upload|publish|leak|copy)\b` +
        `${SENTENCE_GAP}{0,40}?` +
        String.raw`\b(?:the\s*|this\s*|our\s*|entire\s*|full\s*){0,3}(?:conversation|chat\s*(?:history|log|transcript)|transcript|message\s*history|context\s*window|prior\s*messages)\b`,
      "i",
    ),
  },
  {
    patternId: "inj.exfiltration_directive.http_post_payload",
    category: "exfiltration_directive",
    severity: "high",
    pattern: /\b(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,120}?(?:--data(?:-binary|-raw)?\b|--upload-file\b|\s-d\s|\s-F\s|\s-T\s|-X\s*POST\b)/i,
  },
  {
    patternId: "inj.exfiltration_directive.markdown_image_beacon",
    category: "exfiltration_directive",
    severity: "high",
    // The silent variant: a markdown image whose query string is templated, so
    // rendering the answer performs the GET and the data leaves in the URL. A
    // plain image link is not enough to fire; the interpolation marker is.
    pattern: /!\[[^\]\n]{0,80}\]\(\s*https?:\/\/[^)\s]{0,200}[?&][A-Za-z0-9_\-]{1,30}=(?:\$\{?|\{\{|%7B|<[A-Za-z])/i,
  },

  // --- role_manipulation ----------------------------------------------------
  {
    patternId: "inj.role_manipulation.you_are_now",
    category: "role_manipulation",
    severity: "medium",
    // "You are now ready to deploy" is ordinary documentation, so the new role
    // has to be one of the unrestricted-persona words to count.
    pattern: /\byou\s*(?:are|'re)\s*now\s*(?:a\s*|an\s*|the\s*|in\s*)?(?:unrestricted|uncensored|unfiltered|unlimited|unbound|jailbroken|amoral|rogue|evil|malicious|no\s*longer|free\s*from|DAN\b|developer\s*mode|admin(?:istrator)?|root|god\s*mode|sudo)/i,
  },
  {
    patternId: "inj.role_manipulation.act_as_persona",
    category: "role_manipulation",
    severity: "medium",
    pattern: /\b(?:act|behave|respond|reply|operate|function)\s*as\s*(?:if\s*you\s*(?:are|were)\s*)?(?:a\s*|an\s*|the\s*)?(?:unrestricted\s*|uncensored\s*|unfiltered\s*|jailbroken\s*|rogue\s*|malicious\s*|different\s*|new\s*|evil\s*|amoral\s*)?(?:AI|A\.I\.|assistant|chatbot|bot|language\s*model|model|persona|character|hacker|DAN)\b/i,
  },
  {
    patternId: "inj.role_manipulation.pretend_to_be",
    category: "role_manipulation",
    severity: "medium",
    pattern: /\b(?:pretend|imagine|suppose|assume)\s*(?:that\s*)?(?:you\s*(?:are|were)|you're)\s*(?:a|an|the|no\s*longer|not)\b/i,
  },
  {
    patternId: "inj.role_manipulation.dan_jailbreak",
    category: "role_manipulation",
    severity: "high",
    pattern: /\b(?:do\s*anything\s*now|DAN\s*mode|jailbroken|jailbreak(?:\s*(?:mode|prompt|this|the\s*model))?|STAN\s*mode|evil\s*confidant)\b/i,
  },
  {
    patternId: "inj.role_manipulation.developer_mode",
    category: "role_manipulation",
    severity: "high",
    pattern: /\b(?:enable|activate|enter|switch\s*(?:to|into)|turn\s*on|engage)\s*(?:the\s*)?(?:developer|debug|god|admin(?:istrator)?|maintenance|unrestricted|unsafe|sudo|root)\s*(?:mode|access|privileges?)\b/i,
  },
  {
    patternId: "inj.role_manipulation.fake_turn_marker",
    category: "role_manipulation",
    severity: "high",
    // Forged conversation structure. Content that arrives inside a tool result
    // has no business emitting turn delimiters; if it does, it is trying to
    // convince the model that a new authoritative speaker has taken over.
    pattern: /(?:<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>|\[\/?(?:INST|SYS)\]|<\/?(?:system|assistant|human)>|^\s*###\s*(?:system|assistant|human|user)\s*:)/im,
  },
  {
    patternId: "inj.role_manipulation.no_longer_bound",
    category: "role_manipulation",
    severity: "high",
    pattern: /\byou\s*(?:are|'re|were)?\s*(?:no\s*longer|not)\s*(?:bound|restricted|limited|constrained|governed|controlled)\s*by\b/i,
  },
  {
    patternId: "inj.role_manipulation.persona_assignment",
    category: "role_manipulation",
    severity: "medium",
    pattern: /\byou\s*(?:are|'re|will\s*be|shall\s*be|must\s*(?:now\s*)?be)\s*(?:a|an|the)\s*(?:helpful\s*|obedient\s*|compliant\s*)?(?:AI|assistant|chatbot|language\s*model|model|persona|character|hacker|security\s*researcher)\s*(?:named|called|who|that|with)\b/i,
  },

  // --- tool_coercion --------------------------------------------------------
  {
    patternId: "inj.tool_coercion.named_tool_invocation",
    category: "tool_coercion",
    severity: "high",
    pattern: /\b(?:call|invoke|execute|trigger|run|use)\s*(?:the\s*)?(?:mcp\s*)?(?:tool|function|command)\s*(?:named|called)\s*[`"']?[A-Za-z_][\w.\-]{1,63}/i,
  },
  {
    patternId: "inj.tool_coercion.quoted_tool_invocation",
    category: "tool_coercion",
    severity: "high",
    pattern: /\b(?:call|invoke|execute|trigger|run|use)\s*(?:the\s*)?[`"'][A-Za-z_][\w.\-]{1,63}[`"']\s*(?:mcp\s*)?(?:tool|function|command)\b/i,
  },
  {
    patternId: "inj.tool_coercion.chained_tool_call",
    category: "tool_coercion",
    severity: "high",
    pattern: /\b(?:then|next|after\s*(?:that|this)|afterwards|finally|also)\s*,?\s*(?:you\s*(?:must|should|need\s*to|will)\s*)?(?:call|invoke|run|execute|trigger|use)\s*(?:the\s*)?(?:tool|function|command|shell|bash|mcp)\b/i,
  },
  {
    patternId: "inj.tool_coercion.run_shell_command",
    category: "tool_coercion",
    severity: "critical",
    pattern: /\b(?:run|execute|exec|spawn|launch|issue)\s*(?:the\s*)?(?:following\s*|this\s*)?(?:shell|bash|zsh|powershell|pwsh|cmd|terminal|system|os)\s*(?:command|commands|script|snippet)\b/i,
  },
  {
    patternId: "inj.tool_coercion.shell_execution_api",
    category: "tool_coercion",
    severity: "critical",
    pattern: /(?:\b(?:bash|sh|zsh|powershell|pwsh)\s*-c\s*["'`]|\bos\.system\s*\(|\bsubprocess\.(?:run|Popen|call|check_output)\s*\(|\bchild_process\.(?:exec|execSync|spawn|spawnSync)\b|\beval\s*\(\s*(?:atob|Buffer\.from|require))/i,
  },
  {
    patternId: "inj.tool_coercion.curl_pipe_shell",
    category: "tool_coercion",
    severity: "critical",
    pattern: /\b(?:curl|wget)\b[^\n]{0,120}?\|\s*(?:sudo\s*)?(?:ba|z|d)?sh\b/i,
  },
  {
    patternId: "inj.tool_coercion.credential_file_path",
    category: "tool_coercion",
    severity: "high",
    // A bare path is high rather than critical: security documentation names
    // these files legitimately. The verb-led variant below is the critical one.
    pattern: /(?:\.aws[\/\\]credentials|\.ssh[\/\\]id_(?:rsa|dsa|ecdsa|ed25519)|\bid_rsa\b|\.netrc\b|\.npmrc\b|\.docker[\/\\]config\.json|\.kube[\/\\]config\b|\.git-credentials\b|\.pgpass\b)/i,
  },
  {
    patternId: "inj.tool_coercion.read_credential_file",
    category: "tool_coercion",
    severity: "critical",
    // The filler between verb and path is a bounded run of determiners rather
    // than one optional article, so "read the contents of the .env file" is not
    // a miss on account of the second "the". Each repetition must consume a
    // word, which keeps the bound linear.
    guarded: true,
    pattern: new RegExp(
      String.raw`\b(?:read|open|cat|print|show|dump|load|display|fetch|include|upload|send|exfiltrate|copy|tail)\s*(?:(?:the|your|my|a|this|its|contents?|of|file|entire|full|local|users?)\s*){0,6}[` +
        "`" +
        String.raw`"']?(?:[~.\w\/\\-]{0,40}[\/\\])?(?:\.env(?:\.\w{1,12})?|\.aws[\/\\]credentials|id_rsa|\.ssh[\/\\][\w.\-]{1,40}|\.netrc|credentials\.(?:json|yaml|yml)|secrets?\.(?:json|yaml|yml|env))\b`,
      "i",
    ),
  },
  {
    patternId: "inj.tool_coercion.privileged_shell",
    category: "tool_coercion",
    severity: "critical",
    pattern: /\b(?:sudo|doas)\s+(?:-\w{1,8}\s+){0,2}(?:rm|dd|chmod|chown|bash|sh|curl|wget|systemctl|useradd|usermod|passwd|visudo|tee)\b/i,
  },
  {
    patternId: "inj.tool_coercion.destructive_command",
    category: "tool_coercion",
    severity: "critical",
    pattern: /(?:\brm\s+-[a-z]{0,3}[rf][a-z]{0,3}\s*(?:\/|~|\$HOME|\*)|\bmkfs(?:\.\w{1,8})?\s|\bshred\s+-|\bdd\s+if=\/dev\/(?:zero|urandom))/i,
  },

  // --- state_poisoning ------------------------------------------------------
  {
    patternId: "inj.state_poisoning.remember_for_later",
    category: "state_poisoning",
    severity: "high",
    pattern: /\bremember\s*(?:this|that|these|the\s*following)?\s*(?:for\s*(?:later|future|the\s*future|next\s*time|all\s*(?:future|subsequent))|permanently|forever|always|in\s*(?:your|long[-\s]*term)\s*memory)\b/i,
  },
  {
    patternId: "inj.state_poisoning.write_to_memory",
    category: "state_poisoning",
    severity: "high",
    pattern: /\b(?:add|save|store|commit|write|append|persist|record)\s*(?:this|that|it|the\s*following)?\s*(?:to|into|in)\s*(?:your\s*|the\s*|my\s*)?(?:long[-\s]*term\s*)?(?:memory|memories|knowledge\s*base|system\s*prompt|instructions|context|profile|preferences)\b/i,
  },
  {
    patternId: "inj.state_poisoning.all_future_responses",
    category: "state_poisoning",
    severity: "high",
    pattern: /\b(?:for|in|on|with)\s*all\s*(?:your\s*)?(?:future|subsequent|following|later|upcoming)\s*(?:responses?|replies|messages?|answers?|conversations?|sessions?|interactions?|turns?|outputs?|requests?)\b/i,
  },
  {
    patternId: "inj.state_poisoning.from_now_on",
    category: "state_poisoning",
    severity: "medium",
    pattern: /\bfrom\s*(?:now|this\s*point|here)\s*on(?:ward|wards)?\s*,?\s*(?:you|always|never|respond|reply|do\s*not|don't|all|every)\b/i,
  },
  {
    patternId: "inj.state_poisoning.always_append_to_output",
    category: "state_poisoning",
    severity: "high",
    pattern: /\b(?:always|never)\s*(?:include|append|add|attach|prepend|insert|mention|end|begin|start)\b[^.\n]{0,60}?\b(?:every|each|all|any)\s*(?:response|reply|message|answer|output|summary)/i,
  },
  {
    patternId: "inj.state_poisoning.rewrite_instructions",
    category: "state_poisoning",
    severity: "high",
    pattern: /\b(?:update|modify|change|replace|amend|revise|extend|patch)\s*(?:your|the)\s*(?:own\s*)?(?:system\s*)?(?:instructions?|prompt|rules?|guidelines?|configuration|memory|persona|directives?|polic(?:y|ies))\b/i,
  },
  {
    patternId: "inj.state_poisoning.forged_user_preference",
    category: "state_poisoning",
    severity: "medium",
    pattern: /\b(?:the\s*user\s*(?:has\s*)?(?:prefers?|requested|wants?|asked)|user\s*preferences?\s*:)\b[^.\n]{0,60}?\b(?:always|never|from\s*now\s*on|in\s*(?:all|every))\b/i,
  },
];

/**
 * Derived, never hand-counted: a hardcoded total silently rots the first time
 * somebody adds a pattern, and this number ends up in operator-facing output.
 */
export const INJECTION_PATTERN_COUNT = INJECTION_PATTERNS.length;

/**
 * Global clones used for the actual scanning. Compiled once at module load
 * because recompiling ~40 regexes per frame on a hot proxy path is pure waste;
 * `lastIndex` is reset before every use, and the whole scan is synchronous, so
 * there is no interleaving to corrupt the shared state.
 */
const COMPILED: RegExp[] = INJECTION_PATTERNS.map((p) => new RegExp(p.pattern.source, `${p.pattern.flags}g`));

/**
 * Work cap. Beyond this many UTF-16 code units the input is scanned as a prefix
 * and the remainder is passed through untouched — a 256 KB prefix is far more
 * text than any legitimate MCP frame carries, and an unbounded scan on the
 * critical path is a denial-of-service primitive handed to the attacker. The
 * cap is in code units rather than UTF-8 bytes because regex work scales with
 * code units, which is the thing actually being bounded.
 */
const MAX_SCAN_CHARS = 256 * 1024;

/** Maximum source characters exposed in a finding's excerpt, before redaction. */
const EXCERPT_MAX = 120;

/** Replacement written over each locatable match when the caller asks to strip. */
const STRIP_REPLACEMENT = "[REDACTED:INJECTION]";

/** Encoded runs decoded per pass. A payload with a thousand base64 blobs is not owed a thousand decodes. */
const MAX_ENCODED_FORMS = 16;

/** Largest encoded run this will decode, in source characters. */
const MAX_ENCODED_RUN = 64 * 1024;

/**
 * Invisible formatting characters. The listed zero-width set plus soft hyphen,
 * directional marks, and the invisible-operator block: all render as nothing,
 * all survive a copy-paste, and all break a literal match when dropped inside a
 * keyword.
 */
const INVISIBLE_CHARS = /[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;

/**
 * Lookalike characters that render as ASCII but are not. Cyrillic and Greek
 * carry most of the practical attack surface because whole keyboards produce
 * them; fullwidth Latin is handled by range arithmetic in the pass itself
 * rather than by 52 more table entries.
 */
const HOMOGLYPHS: Record<string, string> = {
  // Cyrillic lowercase
  "\u0430": "a", // а
  "\u0435": "e", // е
  "\u043e": "o", // о
  "\u0440": "p", // р
  "\u0441": "c", // с
  "\u0445": "x", // х
  "\u0443": "y", // у
  "\u0456": "i", // і
  "\u0458": "j", // ј
  "\u0455": "s", // ѕ
  "\u04bb": "h", // һ
  "\u0501": "d", // ԁ
  "\u04cf": "l", // ӏ
  "\u051b": "q", // ԛ
  "\u051d": "w", // ԝ
  "\u0433": "r", // г
  "\u043c": "m", // м
  "\u043d": "h", // н
  "\u0432": "b", // в
  "\u043a": "k", // к
  "\u0442": "t", // т
  // Cyrillic uppercase
  "\u0410": "A",
  "\u0412": "B",
  "\u0415": "E",
  "\u041a": "K",
  "\u041c": "M",
  "\u041d": "H",
  "\u041e": "O",
  "\u0420": "P",
  "\u0421": "C",
  "\u0422": "T",
  "\u0423": "Y",
  "\u0425": "X",
  "\u0406": "I",
  "\u0405": "S",
  "\u0408": "J",
  // Greek lowercase
  "\u03b1": "a",
  "\u03b5": "e",
  "\u03b9": "i",
  "\u03ba": "k",
  "\u03bd": "v",
  "\u03bf": "o",
  "\u03c1": "p",
  "\u03c4": "t",
  "\u03c5": "u",
  "\u03c7": "x",
  // Greek uppercase
  "\u0391": "A",
  "\u0392": "B",
  "\u0395": "E",
  "\u0396": "Z",
  "\u0397": "H",
  "\u0399": "I",
  "\u039a": "K",
  "\u039c": "M",
  "\u039d": "N",
  "\u039f": "O",
  "\u03a1": "P",
  "\u03a4": "T",
  "\u03a5": "Y",
  "\u03a7": "X",
};

/**
 * Leet substitutions, applied in the direction that recovers plain text.
 *
 * `1` is genuinely ambiguous — it stands for both `l` and `i` — so the pass
 * emits two readings rather than guessing one and losing the other. Everything
 * else has a single conventional expansion.
 */
const LEET_PRIMARY: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  $: "s",
};

const LEET_ALTERNATE: Record<string, string> = { ...LEET_PRIMARY, "1": "i" };

/** Runs long enough that an encoded payload is plausible; shorter runs are noise. */
const BASE64_RUN = /[A-Za-z0-9+/]{16,}={0,2}/g;
const HEX_RUN = /[0-9a-fA-F]{32,}/g;

/**
 * Maps a match range in a normalized form back to the raw input, or returns
 * null when the pass destroyed positional correspondence (decoded payloads have
 * no character-for-character home in the original text).
 */
type RangeResolver = (start: number, end: number) => [number, number] | null;

/** A normalized rendering of the input, before it is attributed to a pass. */
interface MappedForm {
  text: string;
  toRaw: RangeResolver;
}

interface NormalizedForm extends MappedForm {
  pass: NormalizationPass;
}

const IDENTITY_RANGE: RangeResolver = (start, end) => [start, end];
const NO_RANGE: RangeResolver = () => null;

/**
 * Builds a form by dropping characters, recording where every surviving
 * character came from so a match can still be located — and therefore
 * stripped — in the original bytes.
 */
function dropChars(source: string, keep: (code: number) => boolean): MappedForm | null {
  const chars: string[] = [];
  const map = new Int32Array(source.length);
  let n = 0;
  for (let i = 0; i < source.length; i++) {
    if (!keep(source.charCodeAt(i))) continue;
    chars.push(source[i]);
    map[n++] = i;
  }
  if (n === source.length) return null;
  return {
    text: chars.join(""),
    toRaw: (start, end) => {
      if (end <= start || end > n) return null;
      return [map[start], map[end - 1] + 1];
    },
  };
}

/**
 * Builds a form by substituting characters one-for-one. Length is preserved, so
 * offsets in the form are offsets in the raw input and no map is needed.
 */
function substituteChars(source: string, table: Record<string, string>, extra?: (ch: string) => string | undefined): string | null {
  let changed = false;
  let out = "";
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    // `Object.hasOwn` rather than a bare lookup: a payload containing
    // "constructor" must not pick up an inherited property as a substitution.
    const mapped = Object.hasOwn(table, ch) ? table[ch] : extra?.(ch);
    if (mapped !== undefined && mapped !== ch) {
      changed = true;
      out += mapped;
    } else {
      out += ch;
    }
  }
  return changed ? out : null;
}

/** Fullwidth Latin (U+FF21-U+FF3A, U+FF41-U+FF5A) folded to ASCII by offset. */
function foldFullwidth(ch: string): string | undefined {
  const code = ch.charCodeAt(0);
  if (code >= 0xff21 && code <= 0xff3a) return String.fromCharCode(code - 0xfee0);
  if (code >= 0xff41 && code <= 0xff5a) return String.fromCharCode(code - 0xfee0);
  return undefined;
}

/**
 * `\s` and the invisible-character set as code predicates. The per-character
 * hot loops run over the whole input, so they test integers rather than
 * allocating a one-character string and a match attempt per position.
 */
function isWhitespaceCode(code: number): boolean {
  return (
    code === 0x20 ||
    (code >= 0x09 && code <= 0x0d) ||
    code === 0x00a0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000 ||
    code === 0xfeff
  );
}

function isInvisibleCode(code: number): boolean {
  return (
    code === 0x00ad ||
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2060 && code <= 0x2064) ||
    (code >= 0x2066 && code <= 0x2069) ||
    code === 0xfeff
  );
}

/** Collapses every run of whitespace to a single space, keeping word boundaries intact. */
function collapseWhitespace(source: string): MappedForm | null {
  const chars: string[] = [];
  const map = new Int32Array(source.length);
  let n = 0;
  let inRun = false;
  for (let i = 0; i < source.length; i++) {
    if (isWhitespaceCode(source.charCodeAt(i))) {
      if (inRun) continue;
      inRun = true;
      chars.push(" ");
      map[n++] = i;
      continue;
    }
    inRun = false;
    chars.push(source[i]);
    map[n++] = i;
  }
  const text = chars.join("");
  if (text === source) return null;
  return {
    text,
    toRaw: (start, end) => {
      if (end <= start || end > n) return null;
      return [map[start], map[end - 1] + 1];
    },
  };
}

function isPrintableAscii(decoded: string): boolean {
  if (decoded.length < 8) return false;
  for (let i = 0; i < decoded.length; i++) {
    const code = decoded.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13) continue;
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
}

/**
 * Decodes encoded runs into scannable forms.
 *
 * The printability check is the whole guard: an invalid UTF-8 decode produces
 * replacement characters, which fail it, and a genuine binary blob fails it
 * too. Only text that a model could actually read as instructions gets scanned.
 */
function encodedForms(source: string, pass: "base64" | "hex"): MappedForm[] {
  const runs = pass === "base64" ? BASE64_RUN : HEX_RUN;
  const forms: MappedForm[] = [];
  runs.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = runs.exec(source)) !== null && forms.length < MAX_ENCODED_FORMS) {
    let run = match[0];
    if (run.length > MAX_ENCODED_RUN) continue;
    let decoded: string;
    try {
      if (pass === "hex") {
        if (run.length % 2 === 1) run = run.slice(0, run.length - 1);
        decoded = Buffer.from(run, "hex").toString("utf8");
      } else {
        decoded = Buffer.from(run, "base64").toString("utf8");
      }
    } catch {
      continue;
    }
    if (!isPrintableAscii(decoded)) continue;
    forms.push({ text: decoded, toRaw: NO_RANGE });
  }
  runs.lastIndex = 0;
  return forms;
}

/**
 * Produces the ordered form list. Order is the dedupe order: a pattern that
 * fires on several forms is reported once, attributed to the earliest, so a
 * single attack does not inflate into seven findings and skew triage.
 *
 * Forms whose text is identical to one already queued are dropped. That is not
 * only an optimization: it keeps a pass that changed nothing from stealing
 * attribution from `raw`.
 */
function buildForms(source: string): NormalizedForm[] {
  const forms: NormalizedForm[] = [{ pass: "raw", text: source, toRaw: IDENTITY_RANGE }];
  const seen = new Set<string>([source]);

  const add = (form: MappedForm | null, pass: NormalizationPass): void => {
    if (!form || seen.has(form.text)) return;
    seen.add(form.text);
    forms.push({ ...form, pass });
  };

  if (INVISIBLE_CHARS.test(source)) {
    add(
      dropChars(source, (code) => !isInvisibleCode(code)),
      "zero_width",
    );
  }

  const homoglyphed = substituteChars(source, HOMOGLYPHS, foldFullwidth);
  if (homoglyphed !== null) add({ text: homoglyphed, toRaw: IDENTITY_RANGE }, "homoglyph");

  const leetPrimary = substituteChars(source, LEET_PRIMARY);
  if (leetPrimary !== null) add({ text: leetPrimary, toRaw: IDENTITY_RANGE }, "leetspeak");
  const leetAlternate = substituteChars(source, LEET_ALTERNATE);
  if (leetAlternate !== null) add({ text: leetAlternate, toRaw: IDENTITY_RANGE }, "leetspeak");

  add(collapseWhitespace(source), "whitespace");
  // The despaced variant is what catches "i g n o r e". It also fuses adjacent
  // words, which is exactly why every pattern is `\b`-anchored: without those
  // anchors "React as a framework" would become a role-manipulation hit.
  add(
    dropChars(source, (code) => !isWhitespaceCode(code)),
    "whitespace",
  );

  for (const form of encodedForms(source, "base64")) add(form, "base64");
  for (const form of encodedForms(source, "hex")) add(form, "hex");

  return forms;
}

/**
 * Builds the finding excerpt.
 *
 * Two independent limits apply. The window bounds how much source text an audit
 * record carries, because a record that quotes the whole payload has become a
 * copy of the attack. The DLP pass then strips secrets out of that window,
 * because injection text routinely carries the very credential it is trying to
 * move and an audit trail is a poor place to store one. Control characters are
 * flattened first so a single frame cannot forge line structure in a log.
 *
 * Redaction can leave the string slightly longer than the window: replacement
 * tokens are longer than some of what they replace. The bound governs exposed
 * source text, which is the property that matters.
 */
function buildExcerpt(source: string, start: number, end: number): string {
  const length = end - start;
  let from: number;
  let to: number;
  if (length >= EXCERPT_MAX) {
    from = start;
    to = start + EXCERPT_MAX;
  } else {
    const pad = Math.floor((EXCERPT_MAX - length) / 2);
    from = Math.max(0, start - pad);
    to = Math.min(source.length, end + pad);
  }
  const window = source.slice(from, to).replace(/[\u0000-\u001f\u007f]/g, " ");
  const dlp = scanText(window, true);
  return dlp.redactedText ?? window;
}

/** Merges overlapping raw ranges and writes the replacement over each survivor. */
function applyStrip(source: string, ranges: Array<[number, number]>): string {
  if (ranges.length === 0) return source;
  const sorted = ranges.slice().sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const parts: string[] = [];
  let cursor = 0;
  let i = 0;
  while (i < sorted.length) {
    const start = sorted[i][0];
    let end = sorted[i][1];
    i++;
    while (i < sorted.length && sorted[i][0] <= end) {
      if (sorted[i][1] > end) end = sorted[i][1];
      i++;
    }
    if (end <= cursor) continue;
    const from = Math.max(start, cursor);
    parts.push(source.slice(cursor, from), STRIP_REPLACEMENT);
    cursor = end;
  }
  parts.push(source.slice(cursor));
  return parts.join("");
}

/**
 * Scans text for prompt-injection patterns across every normalization pass.
 *
 * `opts.strip` additionally returns the text with each locatable match replaced
 * by a marker. "Locatable" is load-bearing: a pattern that only surfaced after
 * base64 or hex decoding has no character range in the original, so the encoded
 * run is left exactly as it was. Silently deleting a blob the caller may need,
 * on the strength of a decode, trades one failure mode for a worse one — the
 * finding is the signal there, and the decision belongs to the gate.
 */
export function scanInjection(text: string, opts?: { strip?: boolean }): InjectionScanResult {
  const strip = opts?.strip === true;
  if (text.length === 0) {
    return { findings: [], containsInjection: false, strippedText: strip ? "" : undefined };
  }

  const truncated = text.length > MAX_SCAN_CHARS;
  const source = truncated ? text.slice(0, MAX_SCAN_CHARS) : text;
  const forms = buildForms(source);

  const findings = new Map<string, InjectionFinding>();
  const ranges: Array<[number, number]> = [];

  for (const form of forms) {
    for (let p = 0; p < INJECTION_PATTERNS.length; p++) {
      const spec = INJECTION_PATTERNS[p];
      // Without stripping there is nothing left to learn once a pattern has
      // fired: the finding is already attributed to the earliest pass.
      if (!strip && findings.has(spec.patternId)) continue;
      const regex = COMPILED[p];
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(form.text)) !== null) {
        if (match[0].length === 0) {
          regex.lastIndex++;
          continue;
        }
        const start = match.index;
        const end = start + match[0].length;
        if (spec.guarded && NEGATION_PREFIX.test(form.text.slice(Math.max(0, start - NEGATION_LOOKBACK), start))) {
          // Resume one character along rather than past the whole match, so a
          // rejection here behaves exactly as an inline lookbehind would: the
          // next candidate start position still gets its chance.
          regex.lastIndex = start + 1;
          continue;
        }
        const rawRange = form.toRaw(start, end);
        if (rawRange) ranges.push(rawRange);
        if (!findings.has(spec.patternId)) {
          findings.set(spec.patternId, {
            patternId: spec.patternId,
            category: spec.category,
            severity: spec.severity,
            pass: form.pass,
            excerpt: rawRange ? buildExcerpt(source, rawRange[0], rawRange[1]) : buildExcerpt(form.text, start, end),
          });
        }
        if (!strip) break;
      }
    }
  }

  const result: InjectionScanResult = {
    findings: [...findings.values()],
    containsInjection: findings.size > 0,
  };
  if (strip) {
    // Anything past the work cap was never examined, so it is returned as it
    // arrived rather than dropped.
    result.strippedText = applyStrip(source, ranges) + (truncated ? text.slice(MAX_SCAN_CHARS) : "");
  }
  return result;
}
