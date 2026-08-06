import type { RegisteredAgent } from "./registry";

/**
 * Per-agent egress budgets: requests and bytes over a sliding window.
 *
 * This is NOT a second flood guard. RuntimeFloodGuard (src/runtime/floodguard.ts) keys on
 * sessionId and actor and gates the /evaluate, tool, and approval paths; it never sees a
 * proxied connection, because a TCP connect has no session and no AgentContext until this
 * layer builds one. The two compose rather than overlap: FloodGuard protects the control
 * surfaces from a runaway loop, this protects the internet from one agent in a fleet. An
 * agent that trips FloodGuard has flooded the API; an agent that trips this has spent its
 * egress allowance.
 *
 * What is enforced exactly, and what is not:
 *
 *   maxRequests  Exact. Checked at admission, before any upstream socket is opened. The
 *                (N+1)th connection in the window is refused and never reaches the network.
 *
 *   maxBytes     Enforced at admission, not mid-stream. Bytes are attributable only once a
 *                connection closes and the proxy knows how many crossed it, so a single
 *                connection can carry more than the entire window's budget; what the ceiling
 *                does is refuse the NEXT admission. Cutting a live tunnel at a byte count
 *                would mean tearing down a socket the agent is mid-response on, and a stream
 *                truncated at an arbitrary offset is a corruption bug wearing a policy hat.
 *                If you need a hard cap per connection, that is a different control.
 *
 * A refused attempt does not consume budget. Charging for a denial means an agent that keeps
 * retrying against a closed door never recovers when the window rolls, which turns a rate
 * limit into a permanent outage triggered by the client's own retry loop.
 */

/** One admitted connection: when it happened and what it eventually cost. */
interface WindowEntry {
  at: number;
  bytes: number;
}

interface AgentLedger {
  entries: WindowEntry[];
  /** Rows for connections still open, so bytes land on the row that was admitted for them. */
  open: Map<number, WindowEntry>;
  admitted: number;
  nextTicket: number;
}

/** The counters as they stood when the decision was made. */
export interface BudgetCounters {
  windowSeconds: number;
  requests: number;
  maxRequests: number | null;
  bytes: number;
  maxBytes: number | null;
}

/** What admitting one connection did to the window. */
export interface BudgetCharge {
  /** The window inclusive of this connection. Null when the agent declares no budget. */
  counters: BudgetCounters | null;
  /**
   * Handle for attributing this connection's bytes when it closes. Null when the agent has
   * no budget, in which case there is nothing to attribute.
   */
  ticket: number | null;
}

/** Per-agent totals for the fleet route and the dashboard. */
export interface BudgetSnapshotRow {
  agentId: string;
  windowSeconds: number;
  requests: number;
  maxRequests: number | null;
  bytes: number;
  maxBytes: number | null;
  /** Connections charged to this agent since the process started, across all windows. */
  admittedTotal: number;
}

export class AgentBudgetLedger {
  private readonly ledgers = new Map<string, AgentLedger>();

  /**
   * Charge one connection to this agent's window and hand back a ticket for its bytes.
   *
   * Deliberately NOT a gate. Whether the agent may open the connection at all is decided in
   * src/runtime/enforcement.ts, from the window this ledger reports through `counters()`,
   * alongside every other reason a connection can be refused. Splitting it that way is what
   * makes "a refused connection costs nothing" structural rather than a flag someone has to
   * remember to pass: enforcement returns before it ever reaches this method.
   *
   * It also means monitor mode charges honestly. Monitor gates nothing, so it always gets
   * here, and the window keeps climbing past the ceiling. That is the number an operator
   * sizing a budget actually needs; a counter that stopped at the limit would answer "are
   * you over" while hiding by how much.
   */
  admit(agent: RegisteredAgent, now = Date.now()): BudgetCharge {
    if (!agent.budget) return { counters: null, ticket: null };

    const { windowSeconds, maxRequests, maxBytes } = agent.budget;
    const fresh: AgentLedger = { entries: [], open: new Map(), admitted: 0, nextTicket: 1 };
    const ledger = this.ledgers.get(agent.id) ?? fresh;
    this.ledgers.set(agent.id, ledger);

    // Expired rows are dropped in place rather than filtered into a new array: this runs once
    // per proxied connection, and rows always leave in arrival order, so the survivors are a
    // suffix and one splice is the whole job.
    const cutoff = now - windowSeconds * 1000;
    let expired = 0;
    while (expired < ledger.entries.length && ledger.entries[expired].at <= cutoff) expired += 1;
    if (expired > 0) ledger.entries.splice(0, expired);

    let bytes = 0;
    for (const entry of ledger.entries) bytes += entry.bytes;

    const entry: WindowEntry = { at: now, bytes: 0 };
    ledger.entries.push(entry);
    ledger.admitted += 1;
    const ticket = ledger.nextTicket++;
    ledger.open.set(ticket, entry);

    return {
      // Reported inclusive of this connection. A record saying "1 of 3 used" for the third
      // admission would read as headroom that does not exist.
      counters: {
        windowSeconds,
        requests: ledger.entries.length,
        maxRequests: maxRequests ?? null,
        bytes,
        maxBytes: maxBytes ?? null,
      },
      ticket,
    };
  }

  /**
   * Attribute a closed connection's bytes to the row admit() opened for it.
   *
   * Keyed by ticket rather than by "most recent row" because connections finish out of order:
   * a long-lived model stream opened first can close after a dozen short ones, and charging
   * its bytes to whichever row happens to be last would scatter one agent's usage across the
   * window at random.
   *
   * A ticket whose row already aged out is dropped along with its bytes. Those bytes belong
   * to a window that has closed; carrying them forward would let one long connection charge a
   * window it never overlapped.
   */
  settle(agentId: string, ticket: number, bytes: number): void {
    const ledger = this.ledgers.get(agentId);
    if (!ledger) return;
    const entry = ledger.open.get(ticket);
    ledger.open.delete(ticket);
    if (entry) entry.bytes += bytes;
  }

  /**
   * The window as it stands, without charging anything.
   *
   * Wanted on every denial path so that a blocked record still carries the agent's standing
   * with its budget. An operator reading a denial should not have to correlate two records to
   * learn whether the agent was near its ceiling when policy stopped it for another reason.
   */
  counters(agent: RegisteredAgent, now = Date.now()): BudgetCounters | null {
    if (!agent.budget) return null;
    const cutoff = now - agent.budget.windowSeconds * 1000;
    let requests = 0;
    let bytes = 0;
    for (const entry of this.ledgers.get(agent.id)?.entries ?? []) {
      if (entry.at <= cutoff) continue;
      requests += 1;
      bytes += entry.bytes;
    }
    return {
      windowSeconds: agent.budget.windowSeconds,
      requests,
      maxRequests: agent.budget.maxRequests ?? null,
      bytes,
      maxBytes: agent.budget.maxBytes ?? null,
    };
  }

  /** Current counters for every budgeted agent, for the fleet view. */
  snapshot(agents: readonly RegisteredAgent[], now = Date.now()): BudgetSnapshotRow[] {
    const rows: BudgetSnapshotRow[] = [];
    for (const agent of agents) {
      if (!agent.budget) continue;
      const ledger = this.ledgers.get(agent.id);
      const cutoff = now - agent.budget.windowSeconds * 1000;
      let requests = 0;
      let bytes = 0;
      for (const entry of ledger?.entries ?? []) {
        if (entry.at <= cutoff) continue;
        requests += 1;
        bytes += entry.bytes;
      }
      rows.push({
        agentId: agent.id,
        windowSeconds: agent.budget.windowSeconds,
        requests,
        maxRequests: agent.budget.maxRequests ?? null,
        bytes,
        maxBytes: agent.budget.maxBytes ?? null,
        admittedTotal: ledger?.admitted ?? 0,
      });
    }
    return rows;
  }

  /** Drop all accounting. For tests, and for a reload that replaces the declared fleet. */
  reset(): void {
    this.ledgers.clear();
  }
}
