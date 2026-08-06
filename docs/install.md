# Install Agentwall

## Requirements

- Node.js 22.12+
- npm 10+
- Linux, for process-level egress attribution. The proxy reads `/proc` to resolve a
  connection back to the process that opened it, so that feature is Linux-only.
  Everything else runs anywhere Node does.
- python3, needed only by `npm run verify:live`

## Local source install

```bash
git clone https://github.com/repsecure/agentwall
cd agentwall
npm install
npm run build
```

Initialize config/policy:

```bash
node dist/cli.js init --mode guarded --allow-hosts api.openai.com
```

Start service:

```bash
node dist/cli.js start
```

## Install `agentwall` launcher command

```bash
./scripts/agentwall-install.sh --yes
agentwall help
```

If your shell PATH includes `/usr/local/bin`, you can now run:

```bash
agentwall init --mode strict --allow-hosts api.openai.com
agentwall doctor
agentwall start
```

## Verify health

```bash
curl http://127.0.0.1:3000/health
```

## The `agentwall-verify` binary

`agentwall-verify` is the independent Go implementation of `docs/audit-format.md`. It shares no
code with the bundled TypeScript verifier, uses only the Go standard library, makes no network
calls, and writes no files. It exists so that a party who does not trust Agentwall, or us, can
still check an audit chain. That purpose is defeated if you cannot check the binary itself, so the
procedure for doing so is below rather than assumed.

Each release attaches five binaries and two manifests:

| Asset | Platform | Linkage | Install path |
| --- | --- | --- | --- |
| `agentwall-verify-linux-amd64` | Linux x86-64 | static | Homebrew, or download |
| `agentwall-verify-linux-arm64` | Linux ARM64 | static | Homebrew, or download |
| `agentwall-verify-darwin-amd64` | macOS Intel | libSystem | Homebrew, or download |
| `agentwall-verify-darwin-arm64` | macOS Apple Silicon | libSystem | Homebrew, or download |
| `agentwall-verify-windows-amd64.exe` | Windows x86-64 | system DLLs | Download only |

Only the Linux binaries are statically linked, and that is stated rather than rounded up because
"static" is the difference between a binary that runs anywhere and one that depends on its host.
`file` reports the two Linux binaries as `statically linked`. The darwin binaries are Mach-O
`DYLDLINK` against `/usr/lib/libSystem.B.dylib`, and the Windows binary imports the usual system
DLLs including `kernel32.dll`, `advapi32.dll` and `ws2_32.dll`. Go cannot emit a fully static
binary for macOS or Windows, because those libraries are the syscall interface on those platforms.

In practice this costs you nothing: all five are built `CGO_ENABLED=0`, so none needs a Go
toolchain, a package install, or any third-party runtime. Each needs only what its own operating
system already ships.

`checksums.txt` covers every release asset. `SHA256SUMS-verifier.txt` covers the five binaries
only, and is the file the Homebrew formula's digests are generated from.

Windows has no package-manager path. Homebrew does not support Windows, so a Windows user
downloads the `.exe` and verifies it by hand with the steps below. That is a real asymmetry and
not an oversight.

### Verify a downloaded verifier binary

Three checks, in increasing order of how little they ask you to trust us. They are not
substitutes for one another.

**1. The download is intact.** Cheap, and the weakest of the three.

You will normally have downloaded one binary, not all five. Both manifests list every file, and
`-c` treats a listed file that is absent as a failure, so checking a whole manifest against a
single download exits non-zero and prints `FAILED open or read` for the other four. Verify the one
line you care about:

```bash
# Linux, and anywhere else with GNU coreutils.
grep 'agentwall-verify-linux-amd64$' SHA256SUMS-verifier.txt | sha256sum -c -

# macOS ships no sha256sum. shasum is preinstalled and reads the same format.
grep 'agentwall-verify-darwin-arm64$' SHA256SUMS-verifier.txt | shasum -a 256 -c -
```

If you did download every asset, check the whole thing. `--ignore-missing` works in both tools if
you want the manifest to skip what you did not download rather than fail on it:

```bash
sha256sum -c checksums.txt                                  # all release assets
sha256sum --ignore-missing -c SHA256SUMS-verifier.txt        # only what is present
shasum -a 256 --ignore-missing -c SHA256SUMS-verifier.txt    # same, on macOS
```

Run these from the directory you downloaded into, since both manifests use bare filenames.

Be clear about what this proves. If you fetched the binary and the checksum file from the same
release page, then anyone who could tamper with the binary could also have edited the checksum
file to match. This check catches truncated downloads, a corrupting proxy, and a mirror serving
the wrong bytes. It does not establish that the release is honest, and it is not evidence about
who built it.

**2. This workflow built it from this tag.** Removes the maintainer, though not the project.

```bash
slsa-verifier verify-artifact agentwall-verify-linux-amd64 \
  --provenance-path <the .intoto.jsonl asset from the release> \
  --source-uri github.com/repsecure/agentwall \
  --source-tag v0.2.0
```

The provenance is signed against the release workflow's own OIDC identity, so this fails if the
binary was built on somebody's laptop and attached by hand, and it fails if the attestation came
from a different repository or a different tag. It still trusts GitHub's signing infrastructure.

**3. Rebuild it yourself.** Removes us from the chain.

```bash
git clone --branch v0.2.0 --depth 1 https://github.com/repsecure/agentwall
cd agentwall
scripts/build-verifier.sh 0.2.0 /tmp/rebuilt
cat /tmp/rebuilt/SHA256SUMS-verifier.txt   # compare against the release's copy
```

The digests should match the release exactly. `scripts/build-verifier.sh` is the same script the
release workflow runs, which is deliberate: when the build lived inline in the workflow YAML, the
documented way to reproduce a release was to read that YAML and retype it, and a procedure nobody
runs is a procedure that quietly stops working.

Two things will make a correct rebuild produce different bytes, both of them expected:

- **A different Go version.** The script pins one exact patch release and refuses to run on
  another, because Go's output changes between them. `scripts/build-verifier.sh
  --print-go-version` prints the required version.
- **Editing the build flags.** `-trimpath` and `-buildvcs=false` are both load-bearing. Without
  the second, Go stamps the git revision into the binary, and a build from a source tarball with
  no `.git` can never match a build from a clone. The release enforces this: it rebuilds from a
  `.git`-less tree at a different path on every run and fails if the digests move.

### Install via Homebrew

Covers macOS and Linux. The formula is generated per release from `SHA256SUMS-verifier.txt`, so
its digests always match the binaries it installs, and it is attached to the release as
`agentwall-verify.rb`.

There is no published tap yet. Homebrew refuses to install a formula that is not in a tap, so
`brew install ./agentwall-verify.rb` does not work and fails with "Homebrew requires formulae to
be in a tap". Put it in a local tap instead:

```bash
brew tap-new repsecure/tap --no-git
cp agentwall-verify.rb "$(brew --repository repsecure/tap)/Formula/"
brew install repsecure/tap/agentwall-verify

agentwall-verify --version     # agentwall-verify 0.2.0
```

Homebrew verifies the formula's digest against the binary it downloads, and aborts on a mismatch.
That inherits the limit from check 1 above: if you took the formula and the binary from the same
release page, matching digests prove consistency, not provenance. Run check 2 or 3 for that.

To remove the tap afterwards: `brew uninstall agentwall-verify && brew untap repsecure/tap`.

### Use it

```bash
agentwall-verify --audit /path/to/audit.jsonl --json
```

Exit status is 0 only when every layer holds. The `--json` output reports the `chained`, `linked`,
and `anchored` layers separately, so a chain that is internally valid but not yet anchored
off-box is distinguishable from a chain that has been edited.

## Container

### What the image gives you, and what it does not

Everything except host-process egress attribution works in a container exactly as it does
on a host: policy evaluation, DLP, approvals, the dashboard, the runtime guards, and the
tamper-evident audit chain.

Attribution is the exception, and it is the product's headline capability, so read this
before deciding the image is what you want. Naming the process behind an outbound
connection is a two-step read of `/proc`: `/proc/net/tcp` maps the client's port to a
socket inode, then `/proc/<pid>/fd` finds the process holding that inode. The first file
is per network namespace. The second is per PID namespace, and resolving its symlinks
additionally requires `PTRACE_MODE_READ`, which means matching the target process's uid
and gid or holding `CAP_SYS_PTRACE`. A default container has its own network namespace,
its own PID namespace, and runs as uid 1000, so all three conditions fail.

A default container therefore records host egress like this:

```json
{"host":"example.com","port":443,"scheme":"https","method":"CONNECT",
 "client":{"pid":null,"comm":null},"decision":"allow"}
```

and the matching audit event carries `agentId: "unattributed"`, `pid: "unknown"`,
`comm: "unknown"`. The destination, the byte counts, the decision, and the hash chain are
all still there. The identity of the caller is not. The README already lists attribution as
Linux-only for the same underlying reason, that it is a `/proc` read; a container is a
second way to lose it, on a Linux host that would otherwise have it. It is recorded rather
than hidden, but a monitor that cannot say which process called out is doing less than the
one this project describes. If naming the process is why you are here, run Agentwall on the
host.

### Run it

Build from a checkout:

```bash
docker build -t agentwall .
```

Run the control plane with the dashboard published:

```bash
docker run -d --name agentwall \
  -p 3000:3000 \
  -e AGENTWALL_OPERATOR_TOKEN="$(openssl rand -hex 32)" \
  -v agentwall-state:/app/state \
  agentwall

curl -fsS http://127.0.0.1:3000/health
```

Without `AGENTWALL_OPERATOR_TOKEN`, every route except `/health` answers 401. `/health` is
unauthenticated so that orchestrators can probe it.

The CLI is in the image but is not its entrypoint, because the entrypoint is the server
and `cli.js start` would run it as a child process that never receives `docker stop`:

```bash
docker run --rm --entrypoint node agentwall /app/dist/cli.js --version
docker run --rm --entrypoint node agentwall /app/dist/cli.js --help
```

### Attribution inside a container: measured

Measured on Linux 6.8 with Docker 29.1.3 and AppArmor enabled, a host client running as
uid 1001 gid 1001, one HTTPS CONNECT through the container's forward proxy each time.

| Flags | Result |
| --- | --- |
| (default) | `pid null`. The client's socket is not in the container's network namespace at all. |
| `--network=host` | `pid null`. The socket is found; only one process is visible, so no owner. |
| `--network=host --pid=host` | `pid null`. 457 of 460 `/proc/<pid>/fd` are unreadable as uid 1000. |
| `--network=host --pid=host --user 1001` | `pid null`. Bare `--user <uid>` assigns gid 0, and the gid must match too. |
| `--network=host --pid=host --user 1001:1001` | `pid null`. AppArmor's `docker-default` profile denies the `/proc/<pid>/fd` symlink read. |
| `--network=host --pid=host --user 1001:1001 --security-opt apparmor=unconfined` | `pid 1300177 comm curl`. Attributes processes of that uid and gid only. |
| `--network=host --pid=host --user 0 --cap-add=SYS_PTRACE --security-opt apparmor=unconfined` | `pid 1300177 comm curl`. Attributes every process on the host. |
| `--pid=host --user 1001:1001 --security-opt apparmor=unconfined` | `pid null`. Without `--network=host` the socket is invisible, so the PID namespace does not matter. |

Two combinations work, and both are expensive:

- `--network=host --pid=host --user <uid>:<gid> --security-opt apparmor=unconfined`
  attributes only processes running as that uid and gid. Lower privilege, narrower reach.
- Adding `--user 0 --cap-add=SYS_PTRACE` attributes every process on the host. Count what
  that run gives up: the network namespace, the PID namespace, the non-root user, and the
  AppArmor profile, and then add the capability to read any process's descriptors and
  memory. What remains of the container is the filesystem and the cgroup. Whether that
  trade is worth making is a judgement about your threat model, but it is not a smaller
  decision than installing Agentwall on the host directly, and it should not be presented
  as one.

`--security-opt apparmor=unconfined` is needed on hosts running Docker's default AppArmor
profile, which Debian and Ubuntu enable out of the box. The profile permits `ptrace` and
`read` only against peers in the same profile, so `readdir` of `/proc/<pid>/fd` succeeds
while `readlink` of its entries returns `EACCES`, and attribution silently returns null
even for a root container holding `CAP_SYS_PTRACE`.

### Sidecar: attribution without host privileges

Sharing namespaces with one agent container, rather than with the host, gives full
attribution of that agent and needs neither host namespace nor an AppArmor change, because
`docker-default` allows the read between two containers under the same profile. Run the
agent as the same uid and gid as Agentwall.

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

Recorded egress then names the process:

```json
{"host":"example.com","port":80,"scheme":"http","method":"GET",
 "client":{"pid":31,"comm":"wget"},"decision":"allow"}
```

### Image behaviour worth knowing

- Runs as uid 1000 (`node`). `/app` is root-owned and unwritable by the process, so code
  execution inside Agentwall cannot rewrite the dashboard JavaScript it serves.
- `/app/state` is the only writable path. Mount it. Approvals, approved manifest hashes,
  and the audit chain live there, and an audit chain that dies with the container is not
  evidence of much. A run using `--user <uid>:<gid>` must bind-mount a host directory that
  uid owns.
- The image runs `examples/container.config.yaml`, which is the monitor-first posture with
  two changes: it binds `0.0.0.0`, because a container's loopback is private and a server
  on `127.0.0.1` inside one is unreachable through `-p`, and it uses port 3000. Under
  `--network=host` there is no network namespace to bound that bind, so pass your own
  config there. Override with `-e AGENTWALL_CONFIG=/etc/agentwall/config.yaml` and a
  read-only mount.
- `HEALTHCHECK` calls `GET /health` with node's built-in `fetch` and checks the response
  body, not just the status code. If you change the config's port, set
  `AGENTWALL_HEALTHCHECK_URL` to match or the container reports unhealthy forever.
- The forward proxy has no default port and does not start until `AGENTWALL_PROXY_PORT` is
  set. Publish that port too when you enable it.
- The base image is pinned by digest, so a rebuild produces the same runtime until the pin
  is deliberately moved.

Published images and their signature verification are documented alongside the release
workflow.

## Uninstall

- User-level launcher only: remove `/usr/local/bin/agentwall`
- Service + common Linux artifacts: `sudo ./scripts/agentwall-uninstall.sh --yes`

