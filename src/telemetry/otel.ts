import * as http from "http";
import * as https from "https";
import { randomBytes } from "crypto";

export interface DecisionTelemetryConfig {
  enabled: boolean;
  endpoint?: string;
  serviceName?: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
}

export interface DecisionTraceRecord {
  routeName: string;
  routePath: string;
  plane?: string;
  action?: string;
  decision?: string;
  riskLevel?: string;
  resultStatus: string;
  startedAtMs: number;
  durationNs?: bigint;
  httpMethod?: string;
  httpStatusCode?: number;
  attributes?: Record<string, string | number | boolean | undefined | null>;
}

export interface DecisionTraceExporter {
  readonly enabled: boolean;
  export(record: DecisionTraceRecord): Promise<void>;
}

interface LoggerLike {
  warn?: (obj: unknown, msg?: string) => void;
}

type AttributeValue = string | number | boolean | undefined | null;

class NoopDecisionTraceExporter implements DecisionTraceExporter {
  readonly enabled = false;

  async export(_record: DecisionTraceRecord): Promise<void> {
    return;
  }
}

class OtlpHttpJsonDecisionTraceExporter implements DecisionTraceExporter {
  readonly enabled = true;

  private readonly endpoint: URL;
  private readonly serviceName: string;
  private readonly timeoutMs: number;
  private readonly headers: Record<string, string>;

  constructor(private readonly config: DecisionTelemetryConfig, private readonly logger?: LoggerLike) {
    this.endpoint = new URL(config.endpoint as string);
    this.serviceName = config.serviceName?.trim() || "agentwall";
    this.timeoutMs = config.timeoutMs ?? 1500;
    this.headers = { ...(config.headers ?? {}) };
  }

  async export(record: DecisionTraceRecord): Promise<void> {
    const payload = this.buildPayload(record);

    try {
      await this.postJson(payload);
    } catch (error) {
      this.logger?.warn?.(
        {
          err: error,
          endpoint: this.endpoint.toString(),
          routeName: record.routeName,
        },
        "Failed to export OTLP-style decision trace"
      );
    }
  }

  private buildPayload(record: DecisionTraceRecord): unknown {
    const durationNs = record.durationNs ?? 0n;
    const startTimeUnixNano = BigInt(record.startedAtMs) * 1_000_000n;
    const endTimeUnixNano = startTimeUnixNano + durationNs;
    const durationMs = Number(durationNs) / 1_000_000;
    const attributes = [
      attribute("agentwall.route_name", record.routeName),
      attribute("agentwall.route_path", record.routePath),
      attribute("agentwall.result_status", record.resultStatus),
      attribute("agentwall.timestamp", new Date(record.startedAtMs).toISOString()),
      attribute("agentwall.duration_ms", durationMs),
      attribute("agentwall.decision", record.decision),
      attribute("agentwall.risk_level", record.riskLevel),
      attribute("agentwall.plane", record.plane),
      attribute("agentwall.action", record.action),
      attribute("http.method", record.httpMethod ?? "POST"),
      attribute("http.route", record.routePath),
      attribute("http.status_code", record.httpStatusCode),
      ...Object.entries(record.attributes ?? {}).map(([key, value]) => attribute(key, value)),
    ].filter((item): item is NonNullable<typeof item> => item !== null);

    return {
      resourceSpans: [
        {
          resource: {
            attributes: [
              attribute("service.name", this.serviceName),
              attribute("service.namespace", "agentwall"),
            ].filter((item): item is NonNullable<typeof item> => item !== null),
          },
          scopeSpans: [
            {
              scope: {
                name: "agentwall.decision-trace",
                version: "0.1.0",
              },
              spans: [
                {
                  traceId: randomBytes(16).toString("hex"),
                  spanId: randomBytes(8).toString("hex"),
                  name: record.routeName,
                  kind: 1,
                  startTimeUnixNano: startTimeUnixNano.toString(),
                  endTimeUnixNano: endTimeUnixNano.toString(),
                  attributes,
                  status: {
                    code: (record.httpStatusCode ?? 200) >= 400 ? 2 : 1,
                    message: record.resultStatus,
                  },
                },
              ],
            },
          ],
        },
      ],
    };
  }

  private postJson(payload: unknown): Promise<void> {
    const body = JSON.stringify(payload);
    const transport = this.endpoint.protocol === "https:" ? https : http;

    return new Promise((resolve, reject) => {
      const request = transport.request(
        {
          protocol: this.endpoint.protocol,
          hostname: this.endpoint.hostname,
          port: this.endpoint.port,
          path: `${this.endpoint.pathname}${this.endpoint.search}`,
          method: "POST",
          headers: {
            "content-type": "application/json",
            "content-length": String(Buffer.byteLength(body)),
            ...this.headers,
          },
          timeout: this.timeoutMs,
        },
        (response) => {
          response.resume();
          response.on("end", () => {
            if ((response.statusCode ?? 500) >= 200 && (response.statusCode ?? 500) < 300) {
              resolve();
              return;
            }

            reject(new Error(`OTLP endpoint responded with status ${response.statusCode ?? "unknown"}`));
          });
        }
      );

      request.on("error", reject);
      request.on("timeout", () => {
        request.destroy(new Error(`OTLP export timed out after ${this.timeoutMs}ms`));
      });
      request.write(body);
      request.end();
    });
  }
}

export function createDecisionTraceExporter(config?: DecisionTelemetryConfig, logger?: LoggerLike): DecisionTraceExporter {
  if (!config?.enabled) {
    return new NoopDecisionTraceExporter();
  }

  if (!config.endpoint) {
    logger?.warn?.({ telemetry: config }, "Decision trace export enabled without an endpoint; exporter disabled");
    return new NoopDecisionTraceExporter();
  }

  try {
    return new OtlpHttpJsonDecisionTraceExporter(config, logger);
  } catch (error) {
    logger?.warn?.({ err: error, telemetry: config }, "Invalid OTLP-style telemetry configuration; exporter disabled");
    return new NoopDecisionTraceExporter();
  }
}

function attribute(key: string, value: AttributeValue): { key: string; value: Record<string, string | number | boolean> } | null {
  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value === "string") {
    return { key, value: { stringValue: value } };
  }

  if (typeof value === "boolean") {
    return { key, value: { boolValue: value } };
  }

  if (Number.isInteger(value)) {
    return { key, value: { intValue: value } };
  }

  return { key, value: { doubleValue: value } };
}
