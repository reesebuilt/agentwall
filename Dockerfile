# Agentwall container image.
#
# What this image is for, stated before anything else, because the honest answer is
# narrower than "run Agentwall":
#
#   - The control plane. Policy evaluation, DLP, approvals, the dashboard, the runtime
#     guards, and the tamper-evident audit chain all work exactly as they do on a host,
#     because none of them read another process's /proc.
#   - Egress attribution for processes that share the container's PID and network
#     namespaces, which is the sidecar case: `--network=container:agent
#     --pid=container:agent`, with the agent running as the same uid and gid, attributes
#     that agent fully and needs no host namespace and no AppArmor change.
#   - Trying Agentwall without installing Node.
#
# What it is NOT for by default: attributing egress to processes on the HOST. Attribution
# maps a client socket to its owner by reading /proc/net/tcp, which is per network
# namespace, and then /proc/<pid>/fd, which is per PID namespace and gated by
# PTRACE_MODE_READ. A container has its own of both namespaces, so a host agent's
# connection resolves to no process and the record carries pid null, comm unknown. That is
# a real reduction of the product's headline capability, not a rough edge. It is recorded
# honestly rather than hidden: the ledger says null, the audit event's agentId says
# "unattributed", and docs/install.md gives the measured flag matrix, including the two
# combinations that restore host attribution and the privilege each one costs.

# Base pinned by digest, not by tag. `node:22-slim` is a moving target: the same tag
# resolves to different bytes week to week, so a tag-pinned build is not reproducible and
# a rebuild can quietly change the runtime under a signed release. The trailing comment
# names the tag the digest belonged to when it was resolved; Dependabot's docker ecosystem
# opens the bump PRs against this line.
FROM node:22-slim@sha256:f576cc608b02e6b04bb0700e13be83eb5ceb7bb24584c3181b0f4ecfa0cd0edf AS build

WORKDIR /app

# Manifests first so the dependency layer survives a source-only edit.
COPY package.json package-lock.json ./

# --ignore-scripts: an install script runs arbitrary code from a dependency at image build
# time, with the build's filesystem and network. No dependency in this tree needs one, so
# the capability is declined rather than trusted. `npm ci` also refuses to proceed when
# package-lock.json disagrees with package.json, which is what makes the build reproducible.
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Drop devDependencies from the tree the runtime stage copies. The compiler, the test
# runner, and ts-node are build-time tools; carrying them into a shipped image means
# shipping their transitive CVEs and giving anyone who reaches code execution a compiler.
RUN npm prune --omit=dev


FROM node:22-slim@sha256:f576cc608b02e6b04bb0700e13be83eb5ceb7bb24584c3181b0f4ecfa0cd0edf AS runtime

# Production mode for the dependency tree, and a hint to fastify and pino that this is
# not a development process.
ENV NODE_ENV=production

WORKDIR /app

# Only the pruned dependency tree and the compiled output cross the stage boundary. src/,
# tsconfig.json, and the devDependency tree stay behind in the build stage.
#
# Nothing is chowned to the runtime user. Everything the process executes stays root-owned
# and unwritable by it, so code execution inside Agentwall does not get to rewrite the
# dashboard JavaScript it serves to an operator's browser, or its own dist/.
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY public ./public
COPY examples ./examples
COPY package.json ./

# COPY preserves the mode of the build context, so these three paths arrive carrying the
# umask of whoever ran `docker build`. On a machine with umask 077 that is 0600, and the
# image then only works for uid 1000: `--user 1001` cannot read the policy file and the
# process exits at startup. Attribution needs `--user`, so this would break the one flag
# combination the image exists to support. Normalizing here also makes the image
# independent of the builder's umask, which a release artifact has to be.
# a=rX is read for everyone, traverse on directories, write for nobody.
RUN chmod -R a=rX /app/public /app/examples && chmod a=r /app/package.json

# The one writable path: approvals, approved manifest hashes, and (when
# AGENTWALL_AUDIT_FILE points here) the audit chain.
#
# Group 0 and group-writable, because `docker run --user <uid>` with no group assigns
# gid 0, and that is the common form. It does not cover every case: attributing a host
# process requires matching its gid as well as its uid, so that run passes
# `--user <uid>:<gid>` and lands outside both owner and group here. Such a run bind-mounts
# a host directory it owns over this path, which is what it should be doing anyway for an
# audit chain that has to outlive the container.
#
# No VOLUME instruction. It would create an anonymous volume on every `docker run`,
# initialized with uid 1000 ownership, which a run using `--user 1001:1001` cannot write
# to: a declared convenience that breaks the documented flags, plus a new orphan volume
# per container start.
RUN install -d -o node -g 0 -m 0775 /app/state

# Non-root. uid 1000 comes from the base image. It is deliberately NOT the uid of any host
# agent, and that mismatch alone is enough to make host-process attribution return null:
# reading /proc/<pid>/fd requires matching the target's uid and gid, or CAP_SYS_PTRACE.
# See docs/install.md, "Attribution inside a container", for the measured matrix.
USER node

# 3000 is the port the shipped container config binds. 3015 is the port
# examples/monitor-first.config.yaml uses, for an operator who mounts that file instead.
# The forward proxy has no default port at all: it starts only when
# AGENTWALL_PROXY_PORT is set, so publish that port explicitly when enabling it.
EXPOSE 3000 3015

# The container binds 0.0.0.0 because a container's loopback is private. The file explains
# the tradeoff; override it with -e AGENTWALL_CONFIG plus a read-only mount.
ENV AGENTWALL_CONFIG=/app/examples/container.config.yaml

# The healthcheck calls the real endpoint, GET /health from src/routes/health.ts, and
# checks the documented body rather than settling for any 200: a reverse proxy or a
# misrouted port can return 200 from something that is not Agentwall. node's global fetch
# is used because the image ships no curl or wget, and adding one to satisfy a healthcheck
# would enlarge the attack surface of every running container to save four lines.
# The URL is an env var so that overriding the config's port does not silently leave the
# container reporting unhealthy forever.
ENV AGENTWALL_HEALTHCHECK_URL=http://127.0.0.1:3000/health
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --start-interval=2s --retries=3 \
  CMD ["node", "-e", "fetch(process.env.AGENTWALL_HEALTHCHECK_URL).then(r=>r.ok?r.json():Promise.reject(r.status)).then(b=>process.exit(b.status===\"ok\"?0:1)).catch(()=>process.exit(1))"]

# The server is PID 1 so that `docker stop` delivers SIGTERM to it directly. The CLI is
# reachable at /app/dist/cli.js via --entrypoint; it is not the entrypoint itself because
# `cli.js start` spawns the server as a child, and a PID 1 that does not forward signals
# turns every `docker stop` into a ten second wait followed by SIGKILL.
ENTRYPOINT ["node", "/app/dist/index.js"]
