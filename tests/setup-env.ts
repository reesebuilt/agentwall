/**
 * Jest global setup.
 *
 * Route tests use app.inject(), which presents as loopback, so they authenticate via
 * the loopback-dev path rather than every suite carrying a token fixture.
 *
 * This is deliberately NOT a blanket auth bypass: loopback-dev is opt-in, off in
 * production, and tests/operator-auth.test.ts exercises the real bearer-token path
 * including wrong-token and remote-address rejection. tests/route-auth.test.ts proves
 * protected routes still 401 when the escape hatch is off, so "auth exists and works"
 * stays covered rather than being assumed away here.
 */
process.env.AGENTWALL_ALLOW_LOOPBACK_DEV = "1";

/**
 * Point the runtime-context probe at a committed fixture.
 *
 * state.ts resolves AGENTWALL_AGENT_HOME once at module load, so this must be set before any
 * import of it. Without this the dashboard test asserts "configured" against whatever
 * happens to exist in the developer's home directory: it passed on the author's box and
 * failed for every other checkout and on CI. A test that depends on un-committed host
 * state is not a test.
 */
import { join } from "path";
process.env.AGENTWALL_AGENT_HOME = join(__dirname, "fixtures", "runtime-home");
