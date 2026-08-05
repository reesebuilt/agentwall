import * as fs from "fs";
import * as path from "path";
import { ApprovalRequest, ApprovalResponse } from "../types";

export type ApprovalPersistenceBackend = "memory" | "file";

export interface PersistedPendingApproval {
  requestId: string;
  request: ApprovalRequest;
  createdAt: number;
  expiresAt: number;
}

export interface PersistedApprovalDecision {
  requestId: string;
  request: ApprovalRequest;
  response: ApprovalResponse;
  createdAt: number;
}

interface ApprovalStoreFile {
  version: 1;
  pending: PersistedPendingApproval[];
  history: PersistedApprovalDecision[];
}

const EMPTY_STORE: ApprovalStoreFile = {
  version: 1,
  pending: [],
  history: [],
};

export class ApprovalQueueStore {
  private readonly backend: ApprovalPersistenceBackend;
  private readonly filePath?: string;

  constructor(backend: ApprovalPersistenceBackend, filePath?: string) {
    this.backend = backend;
    this.filePath = filePath ? path.resolve(filePath) : undefined;
  }

  load(): ApprovalStoreFile {
    if (this.backend === "memory" || !this.filePath) {
      return {
        version: 1,
        pending: [],
        history: [],
      };
    }

    if (!fs.existsSync(this.filePath)) {
      return {
        version: 1,
        pending: [],
        history: [],
      };
    }

    const raw = fs.readFileSync(this.filePath, "utf-8");
    const parsed = JSON.parse(raw) as Partial<ApprovalStoreFile>;
    return {
      version: 1,
      pending: Array.isArray(parsed.pending) ? parsed.pending : [],
      history: Array.isArray(parsed.history) ? parsed.history : [],
    };
  }

  save(state: { pending: PersistedPendingApproval[]; history: PersistedApprovalDecision[] }): void {
    if (this.backend === "memory" || !this.filePath) {
      return;
    }

    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const payload: ApprovalStoreFile = {
      version: 1,
      pending: state.pending,
      history: state.history,
    };
    const tempPath = `${this.filePath}.tmp`;
    fs.writeFileSync(tempPath, JSON.stringify(payload, null, 2));
    fs.renameSync(tempPath, this.filePath);
  }

  clear(): void {
    if (this.backend === "memory" || !this.filePath) {
      return;
    }

    if (fs.existsSync(this.filePath)) {
      fs.unlinkSync(this.filePath);
    }
  }
}
