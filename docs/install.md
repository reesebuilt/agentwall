# Install AgentWall

Use this guide to install AgentWall and start its local operator UI.

## Requirements

- Use Node.js 22.12 or later.
- Use npm 10 or later.
- Install `python3` only if you use `npm run verify:live`.
- Use Linux if you need process-level egress attribution.

AgentWall reads `/proc` to map a connection to its source process. This attribution feature works only on Linux. Other features run on each platform that Node.js supports.

## Build from source

**Goal:** Build the AgentWall service and command-line interface.

**Command:**

```bash
git clone https://github.com/repsecure/agentwall
cd agentwall
npm ci
npm run build
```

**Expected result:** npm creates the compiled files in `dist`.

**Common fix:** Install Node.js 22.12 or later if npm reports an unsupported engine.

## Install the `agentwall` launcher

**Goal:** Make the `agentwall` command available to the local shell.

**Command:**

```bash
./scripts/agentwall-install.sh --yes
agentwall help
```

**Expected result:** `agentwall help` prints the command list.

**Common fix:** Add `/usr/local/bin` to `PATH` if the shell cannot find `agentwall`.

## Complete the first run in the local UI

**Goal:** Create safe local files and start AgentWall from the primary setup path.

**Command:**

```bash
agentwall ui
```

**Expected result:** AgentWall prints `http://127.0.0.1:3001` and serves the bootstrap UI there.

1. Open the printed URL in a local browser.
2. Select **Setup** to create the local operator files.
3. Select **Start** to start the service.
4. Open the dashboard link after the service reaches the `running` state.

The setup action uses monitor mode and local bind addresses by default. The bootstrap UI binds to `127.0.0.1:3001`. The service binds to `127.0.0.1:3000`.

Setup creates `agentwall.config.yaml`, `policy.yaml`, and `.agentwall/operator.env`. It also creates the audit path that the environment file names. Setup does not replace an existing configuration unless you use `--force`.

AgentWall creates `.agentwall` with mode `0700` where the platform supports file modes. It writes `.agentwall/operator.env` with mode `0600` where the platform supports file modes. AgentWall never prints the generated operator token.

AgentWall parses only known `KEY=value` entries from `.agentwall/operator.env`. It does not run the file as shell code. An explicit environment variable takes priority over the same generated value.

The UI sends mutations through typed actions. It does not accept an arbitrary shell command. A read-only action shows its status, output, and a copyable CLI command.

**Common fix:** Run `agentwall ui --port 3002` if port `3001` is in use.

Use `--host` only when the bootstrap UI must use another bind address. Use `--service-port` only when the service must use another port. Local-only access is the default.

## Use the direct CLI without the browser

**Goal:** Create the same local files when a browser is unavailable.

**Command:**

```bash
agentwall setup --mode monitor
agentwall start
agentwall doctor
```

**Expected result:** Setup prints the created paths and the next commands. Start loads the generated environment and starts the local service. Doctor reports the local install state.

**Common fix:** Add `--force` to `agentwall setup` only when you intend to replace existing setup files.

Use `--lan` only when you intend to expose the service beyond loopback. Review the host firewall and operator token before you enable LAN access.

The older `init` command remains available for an explicit configuration path.

```bash
agentwall init --mode strict --allow-hosts api.openai.com
agentwall doctor
agentwall start
```

**Expected result:** `init` creates a strict configuration for the named host.

**Common fix:** Use `agentwall setup --mode monitor` for a safer first run if strict mode blocks required traffic.

## Run directly from `dist`

**Goal:** Use the compiled CLI without the installed launcher.

Initialize the configuration and policy files.

```bash
node dist/cli.js init --mode guarded --allow-hosts api.openai.com
```

**Expected result:** AgentWall creates `agentwall.config.yaml` and `policy.yaml` in the current directory.

Start the service.

```bash
node dist/cli.js start
```

**Expected result:** The service listens on the host and port in `agentwall.config.yaml`.

**Common fix:** Run the command from the directory that contains `agentwall.config.yaml`.

## Check service health

**Goal:** Confirm that the local service responds.

**Command:**

```bash
curl http://127.0.0.1:3000/health
```

**Expected result:** The `/health` route returns a successful health response.

**Common fix:** Start AgentWall or use the configured host and port if the connection fails.

## Install the independent audit verifier

`agentwall-verify` implements `docs/audit-format.md` in Go. It shares no code with the TypeScript verifier. It uses only the Go standard library. It makes no network calls and writes no files.

Each release provides these verifier assets.

| Asset | Platform | Linkage | Install path |
| --- | --- | --- | --- |
| `agentwall-verify-linux-amd64` | Linux x86-64 | static | Homebrew or download |
| `agentwall-verify-linux-arm64` | Linux ARM64 | static | Homebrew or download |
| `agentwall-verify-darwin-amd64` | macOS Intel | libSystem | Homebrew or download |
| `agentwall-verify-darwin-arm64` | macOS Apple Silicon | libSystem | Homebrew or download |
| `agentwall-verify-windows-amd64.exe` | Windows x86-64 | system DLLs | download only |

Only the Linux binaries are statically linked. The macOS binaries use `/usr/lib/libSystem.B.dylib`. The Windows binary uses standard Windows system DLLs.

All five binaries use `CGO_ENABLED=0`. They need no Go toolchain or third-party runtime. Windows has no Homebrew install path.

`checksums.txt` covers every release asset. `SHA256SUMS-verifier.txt` covers only the five verifier binaries.

### Check one downloaded binary

**Goal:** Detect an incomplete or corrupt download.

**Command:**

```bash
# Linux, and anywhere else with GNU coreutils.
grep 'agentwall-verify-linux-amd64$' SHA256SUMS-verifier.txt | sha256sum -c -

# macOS ships no sha256sum. shasum is preinstalled and reads the same format.
grep 'agentwall-verify-darwin-arm64$' SHA256SUMS-verifier.txt | shasum -a 256 -c -
```

**Expected result:** The selected binary reports `OK`.

**Common fix:** Select the manifest line that matches the downloaded platform asset.

Run the check from the download directory. A checksum proves file consistency. It does not prove who built the file.

### Check downloaded release assets

**Goal:** Check all present assets against a release manifest.

**Command:**

```bash
sha256sum -c checksums.txt                                  # all release assets
sha256sum --ignore-missing -c SHA256SUMS-verifier.txt        # only what is present
shasum -a 256 --ignore-missing -c SHA256SUMS-verifier.txt    # same, on macOS
```

**Expected result:** Each present asset reports a matching digest.

**Common fix:** Use `--ignore-missing` when you did not download every listed asset.

### Check release provenance

**Goal:** Confirm that the release workflow built the binary from the stated tag.

**Command:**

```bash
slsa-verifier verify-artifact agentwall-verify-linux-amd64 \
  --provenance-path <the .intoto.jsonl asset from the release> \
  --source-uri github.com/repsecure/agentwall \
  --source-tag v0.2.0
```

**Expected result:** `slsa-verifier` accepts the workflow identity, repository, and tag.

**Common fix:** Use the provenance asset and source tag from the same release.

This check trusts the release platform identity and its signature service.

### Rebuild the verifier

**Goal:** Compare a local build with the release binary.

**Command:**

```bash
git clone --branch v0.2.0 --depth 1 https://github.com/repsecure/agentwall
cd agentwall
scripts/build-verifier.sh 0.2.0 /tmp/rebuilt
cat /tmp/rebuilt/SHA256SUMS-verifier.txt   # compare against the release's copy
```

**Expected result:** The local digests match the release digests.

**Common fix:** Run `scripts/build-verifier.sh --print-go-version` and install that exact Go patch release.

Do not change `-trimpath` or `-buildvcs=false`. A different Go version or different flags can produce different bytes.

### Install the verifier with Homebrew

**Goal:** Install the release verifier on macOS or Linux.

The release includes `agentwall-verify.rb`. No published tap exists, so create a local tap.

**Command:**

```bash
brew tap-new repsecure/tap --no-git
cp agentwall-verify.rb "$(brew --repository repsecure/tap)/Formula/"
brew install repsecure/tap/agentwall-verify

agentwall-verify --version     # agentwall-verify 0.2.0
```

**Expected result:** Homebrew verifies the digest and installs `agentwall-verify`.

**Common fix:** Copy the formula into the local tap before you run `brew install`.

Remove the tap with `brew uninstall agentwall-verify && brew untap repsecure/tap`.

### Verify an audit chain

**Goal:** Check every audit-chain layer without a network connection.

**Command:**

```bash
agentwall-verify --audit /path/to/audit.jsonl --json
```

**Expected result:** Exit status `0` means that every required layer holds. JSON reports `chained`, `linked`, and `anchored` separately.

**Common fix:** Read the failed JSON layer before you repair or replace any audit file.

## Run AgentWall in a container

A container supports policy evaluation, DLP, approvals, the dashboard, runtime guards, and the audit chain. A default container cannot attribute host egress to a host process.

AgentWall needs the host network namespace, host PID namespace, and sufficient `/proc` access for host attribution. A default container has none of these conditions.

A default container records host egress without process identity.

```json
{"host":"example.com","port":443,"scheme":"https","method":"CONNECT",
 "client":{"pid":null,"comm":null},"decision":"allow"}
```

The related audit event uses `agentId: "unattributed"`, `pid: "unknown"`, and `comm: "unknown"`. Destination, byte counts, decision, and hash-chain data remain available.

Run AgentWall on the host if you need reliable host-process attribution.

### Build the image

**Goal:** Build a local AgentWall container image.

**Command:**

```bash
docker build -t agentwall .
```

**Expected result:** Docker creates the local `agentwall` image.

**Common fix:** Run the command from the repository root so Docker can read the build context.

### Start the container

**Goal:** Start the control plane and publish the dashboard.

**Command:**

```bash
docker run -d --name agentwall \
  -p 3000:3000 \
  -e AGENTWALL_OPERATOR_TOKEN="$(openssl rand -hex 32)" \
  -v agentwall-state:/app/state \
  agentwall

curl -fsS http://127.0.0.1:3000/health
```

**Expected result:** Docker starts the container and `/health` returns success.

**Common fix:** Set `AGENTWALL_OPERATOR_TOKEN` if protected routes return `401`.

Without `AGENTWALL_OPERATOR_TOKEN`, every route except `/health` returns `401`. `/health` stays unauthenticated for orchestrator probes.

The image entrypoint starts the server. Use these commands to run the CLI instead.

```bash
docker run --rm --entrypoint node agentwall /app/dist/cli.js --version
docker run --rm --entrypoint node agentwall /app/dist/cli.js --help
```

**Expected result:** The commands print the image CLI version or help.

**Common fix:** Build or pull the `agentwall` image before you run these commands.

### Understand container attribution limits

These results use Linux 6.8, Docker 29.1.3, and AppArmor. The host client used user ID 1001 and group ID 1001.

| Flags | Result |
| --- | --- |
| default | `pid null`. The socket is outside the container network namespace. |
| `--network=host` | `pid null`. The socket is visible, but the owner process is not visible. |
| `--network=host --pid=host` | `pid null`. The container user cannot read most process descriptors. |
| `--network=host --pid=host --user 1001` | `pid null`. The group ID does not match. |
| `--network=host --pid=host --user 1001:1001` | `pid null`. The default AppArmor profile denies descriptor link reads. |
| `--network=host --pid=host --user 1001:1001 --security-opt apparmor=unconfined` | Attribution works for processes with that user ID and group ID. |
| `--network=host --pid=host --user 0 --cap-add=SYS_PTRACE --security-opt apparmor=unconfined` | Attribution works for all host processes. |
| `--pid=host --user 1001:1001 --security-opt apparmor=unconfined` | `pid null`. The socket stays outside the container network namespace. |

The lower-privilege option needs matching user and group IDs. It also needs host network and PID namespaces. It attributes only processes with those IDs.

The root option also needs `CAP_SYS_PTRACE` and an unconfined AppArmor profile. It can read descriptors and memory for every host process. Use it only after a threat-model review.

Debian and Ubuntu enable Docker's default AppArmor profile. That profile can make attribution return `null` even when the container has `CAP_SYS_PTRACE`.

### Use a sidecar for one agent container

**Goal:** Attribute one agent without host namespaces or an AppArmor change.

Run AgentWall and the agent with the same user ID and group ID.

**Command:**

```bash
docker run -d --name agentwall \
  -e AGENTWALL_OPERATOR_TOKEN="$(openssl rand -hex 32)" \
  -e AGENTWALL_PROXY_PORT=3128 \
  -e AGENTWALL_PROXY_LEDGER=/app/state/egress.jsonl \
  -e AGENTWALL_AUDIT_FILE=/app/state/audit.jsonl \
  -v agentwall-state:/app/state \
  agentwall

docker run --rm \
  --network=container:agentwall --pid=container:agentwall --user 1000:1000 \
  -e http_proxy=http://127.0.0.1:3128 -e https_proxy=http://127.0.0.1:3128 \
  your-agent-image
```

**Expected result:** The audit record names the process inside the shared namespaces.

```json
{"host":"example.com","port":80,"scheme":"http","method":"GET",
 "client":{"pid":31,"comm":"wget"},"decision":"allow"}
```

**Common fix:** Use the same user ID and group ID in both containers if attribution remains `null`.

### Container file limits

- The image runs as user ID 1000.
- `/app` is root-owned and not writable by the process.
- `/app/state` is the only writable path.
- Mount `/app/state` to retain approvals, manifest hashes, and the audit chain.
- A custom user needs a host directory that the same user owns.
- The image binds `0.0.0.0:3000` because container loopback cannot serve a published port.
- Use `AGENTWALL_CONFIG` with a read-only mount to supply another configuration.
- Set `AGENTWALL_HEALTHCHECK_URL` when you change the service port.
- Set `AGENTWALL_PROXY_PORT` before you expect the forward proxy to start.
- Publish the proxy port when clients outside the container need it.
- The base image uses a fixed digest until the project updates that digest.

## Uninstall

**Goal:** Remove the launcher or the service files.

Remove only the user-level launcher with `rm /usr/local/bin/agentwall`.

Remove the service and common Linux files with `sudo ./scripts/agentwall-uninstall.sh --yes`.

**Expected result:** The selected AgentWall installation files no longer remain.

**Common fix:** Use `sudo` when the installer placed files in system directories.
