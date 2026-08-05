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
git clone https://github.com/reesebuilt/agentwall
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

## Uninstall

- User-level launcher only: remove `/usr/local/bin/agentwall`
- Service + common Linux artifacts: `sudo ./scripts/agentwall-uninstall.sh --yes`

