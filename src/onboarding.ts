import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";
import * as yaml from "js-yaml";
import { AgentwallConfig } from "./config";

export type OnboardingMode = "monitor" | "guarded" | "strict";

export interface OnboardingOptions {
  mode: OnboardingMode;
  host: string;
  port: number;
  allowedHosts: string[];
  lanAccess: boolean;
}

export const defaultConfig: AgentwallConfig = {
  port: 3000,
  host: "127.0.0.1",
  logLevel: "info",
  approval: {
    mode: "auto",
    timeoutMs: 30000,
    backend: "file",
    persistencePath: "./agentwall-approvals.json",
  },
  policy: {
    defaultDecision: "deny",
    configPath: "./policy.yaml",
  },
  dlp: {
    enabled: true,
    redactSecrets: true,
  },
  egress: {
    enabled: true,
    defaultDeny: true,
    allowPrivateRanges: false,
    allowedHosts: [],
    allowedSchemes: ["https"],
    allowedPorts: [443],
  },
  manifestIntegrity: {
    enabled: true,
  },
  watchdog: {
    enabled: true,
    staleAfterMs: 15000,
    timeoutMs: 30000,
    killSwitchMode: "deny_all",
  },
};

export function createStarterConfig(input: OnboardingOptions): { config: AgentwallConfig; policy: Record<string, unknown> } {
  const mode = input.mode;
  const config: AgentwallConfig = {
    ...defaultConfig,
    host: input.lanAccess ? "0.0.0.0" : input.host,
    port: Number.isFinite(input.port) ? input.port : defaultConfig.port,
    policy: {
      ...defaultConfig.policy,
      defaultDecision: mode === "monitor" ? "allow" : "deny",
      configPath: "./policy.yaml",
    },
    approval: {
      ...defaultConfig.approval,
      mode: mode === "strict" ? "always" : mode === "monitor" ? "never" : "auto",
    },
    egress: {
      ...defaultConfig.egress,
      defaultDeny: mode !== "monitor",
      allowedHosts: input.allowedHosts,
    },
  };

  const policy = {
    version: "1",
    rules: [
      {
        id: "starter:untrusted-web-egress",
        description: "Require review when untrusted web content drives outbound actions",
        plane: "content",
        match: {
          provenance: {
            source: ["web"],
            trustLabel: ["untrusted", "derived"],
          },
          flow: {
            direction: "egress",
            labels: ["external_egress"],
          },
        },
        decision: mode === "monitor" ? "allow" : "approve",
        riskLevel: "high",
        reason: "Untrusted web content is driving outbound activity",
      },
      {
        id: "starter:allow-approved-hosts",
        description: "Allow explicitly approved egress destinations",
        plane: "network",
        match: {
          type: "hostname-equals",
          values: config.egress.allowedHosts,
        },
        decision: "allow",
        riskLevel: "low",
        reason: "Approved destination",
      },
    ],
  };

  return { config, policy };
}

export function writeStarterFiles(baseDir: string, options: OnboardingOptions): { configPath: string; policyPath: string; config: AgentwallConfig } {
  const { config, policy } = createStarterConfig(options);
  const configPath = path.resolve(baseDir, "agentwall.config.yaml");
  const policyPath = path.resolve(baseDir, "policy.yaml");

  fs.writeFileSync(configPath, yaml.dump(config, { noRefs: true }));
  fs.writeFileSync(policyPath, yaml.dump(policy, { noRefs: true }));

  return { configPath, policyPath, config };
}

async function runInteractiveOnboarding() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const ask = (question: string, fallback?: string) =>
    new Promise<string>((resolve) => {
      const suffix = fallback ? ` [${fallback}]` : "";
      rl.question(`${question}${suffix}: `, (answer) => {
        const value = answer.trim();
        resolve(value || fallback || "");
      });
    });

  console.log("\nAgentwall CLI Onboarding\n");
  console.log("This sets up a first-run config for a new user. Start narrow. One workflow. One policy surface.\n");

  const modeRaw = (await ask("Choose operating mode: monitor | guarded | strict", "guarded")).toLowerCase();
  const mode: OnboardingMode = modeRaw === "monitor" || modeRaw === "strict" ? modeRaw : "guarded";
  const host = await ask("Host to bind", defaultConfig.host);
  const port = Number(await ask("Port", String(defaultConfig.port)));
  const allowHosts = await ask("Comma-separated allowed outbound hosts (leave blank for none)", "api.openai.com");
  const lanAccess = (await ask("Allow LAN access? yes | no", "no")).toLowerCase() === "yes";

  const { configPath, policyPath, config } = writeStarterFiles(process.cwd(), {
    mode,
    host,
    port: Number.isFinite(port) ? port : defaultConfig.port,
    allowedHosts: allowHosts
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    lanAccess,
  });

  console.log("\nCreated:");
  console.log(`- ${configPath}`);
  console.log(`- ${policyPath}`);

  console.log("\nNext steps:");
  console.log("1. npm run build");
  console.log("2. npm start");
  console.log(`3. Open http://${config.host}:${config.port}`);
  console.log("4. Run one agent/workflow first and watch the audit + approval views");
  console.log("5. Tighten rules before adding more tools or destinations\n");

  rl.close();
}

if (require.main === module) {
  runInteractiveOnboarding().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
