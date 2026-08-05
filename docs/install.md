# Install Agentwall

## Requirements

- Node.js 20+
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

