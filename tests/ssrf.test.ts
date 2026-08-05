import { describe, expect, it } from "@jest/globals";
import {
  extractHostname,
  inspectNetworkRequest,
  isPrivateHostname,
  isPrivateIp,
  normalizeHostname,
} from "../src/planes/network/ssrf";

describe("SSRF Inspector", () => {
  it("denies external HTTPS URLs by default when not allowlisted", () => {
    const result = inspectNetworkRequest({ url: "https://api.openai.com/v1/chat/completions" });
    expect(result.allowed).toBe(false);
    expect(result.blockedCategory).toBe("default-deny-egress");
    expect(result.egressDenied).toBe(true);
  });

  it("allows external HTTPS URLs when allowlisted", () => {
    const result = inspectNetworkRequest(
      { url: "https://api.openai.com/v1/chat/completions" },
      { allowedHosts: ["api.openai.com"] }
    );
    expect(result.allowed).toBe(true);
    expect(result.ssrf).toBe(false);
  });

  it("blocks localhost", () => {
    const result = inspectNetworkRequest({ url: "http://localhost:9200" });
    expect(result.allowed).toBe(false);
    expect(result.ssrf).toBe(true);
  });

  it("blocks 127.0.0.1", () => {
    const result = inspectNetworkRequest({ url: "http://127.0.0.1/admin" });
    expect(result.allowed).toBe(false);
    expect(result.ssrf).toBe(true);
    expect(result.riskLevel).toBe("critical");
  });

  it("blocks metadata endpoints", () => {
    const result = inspectNetworkRequest(
      { url: "http://169.254.169.254/latest/meta-data/" },
      { allowedSchemes: ["http", "https"], allowedPorts: [80, 443] }
    );
    expect(result.allowed).toBe(false);
    expect(result.blockedCategory).toBe("cloud-metadata");
    expect(result.riskLevel).toBe("critical");
  });

  it("blocks embedded credentials", () => {
    const result = inspectNetworkRequest(
      { url: "https://user:pass@example.com/data" },
      { allowedHosts: ["example.com"] }
    );
    expect(result.allowed).toBe(false);
    expect(result.blockedCategory).toBe("embedded-credentials");
  });

  it("blocks non-https schemes by default", () => {
    const result = inspectNetworkRequest({ url: "http://example.com" }, { allowedHosts: ["example.com"], allowedPorts: [80, 443] });
    expect(result.allowed).toBe(false);
    expect(result.blockedCategory).toBe("blocked-scheme");
  });

  // RFC1918 literal is required here, not a leak: the assertion IS that the inspector
  // classifies a private address as private. A TEST-NET-3 substitute would make this
  // test pass for the wrong reason.
  it("allows private ranges only when explicitly permitted and allowlisted", () => {
    const result = inspectNetworkRequest(
      { url: "https://192.168.1.1/" },
      { allowPrivateRanges: true, allowedHosts: ["192.168.1.1"] }
    );
    expect(result.allowed).toBe(true);
    expect(result.privateRange).toBe(true);
  });

  it("returns high risk for malformed URLs", () => {
    const result = inspectNetworkRequest({ url: "not-a-url" });
    expect(result.allowed).toBe(false);
    expect(result.riskLevel).toBe("high");
  });
});

describe("SSRF Inspector: IPv6", () => {
  // Regression guard for a dead check: `new URL("http://[::1]/").hostname` is "[::1]",
  // while every IPV6_PRIVATE_PATTERN is anchored on the bare address. Bracketed input
  // must behave identically to bare input, or the entire IPv6 private-range table goes
  // dark again and http://[::1]/ walks straight through the inspector.
  const PRIVATE_IPV6 = [
    "::1",
    "::", // unspecified; routes to loopback on most stacks
    "fd00::1",
    "fc00::1",
    "fe80::1",
    "feb0::dead:beef",
    "::ffff:7f00:1", // ::ffff:127.0.0.1, as the URL parser re-serialises it
    "::7f00:1", // IPv4-compatible ::127.0.0.1
    "::ffff:c0a8:101", // ::ffff:192.168.1.1
    "::ffff:a9fe:a9fe", // ::ffff:169.254.169.254 (cloud metadata)
  ];

  for (const address of PRIVATE_IPV6) {
    it(`treats ${address} as private in bare and bracketed form`, () => {
      expect(isPrivateIp(address)).toBe(true);
      expect(isPrivateIp(`[${address}]`)).toBe(true);
    });
  }

  const PUBLIC_IPV6 = [
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "::ffff:808:808", // ::ffff:8.8.8.8: mapped, but the embedded IPv4 is public
  ];

  for (const address of PUBLIC_IPV6) {
    it(`does not treat public ${address} as private`, () => {
      expect(isPrivateIp(address)).toBe(false);
      expect(isPrivateIp(`[${address}]`)).toBe(false);
    });
  }

  it("strips the brackets the URL parser keeps around IPv6 literals", () => {
    // The platform behaviour the whole bug hinges on; pinned so it cannot drift unnoticed.
    expect(new URL("http://[::1]/").hostname).toBe("[::1]");
    expect(normalizeHostname("[::1]")).toBe("::1");
    expect(normalizeHostname("[FD00::1]")).toBe("fd00::1");
    expect(normalizeHostname("Example.COM")).toBe("example.com");
    expect(extractHostname("http://[::1]/")).toBe("::1");
    expect(extractHostname("http://[FD00::1]:8080/admin")).toBe("fd00::1");
  });

  it("treats a DNS-root-dotted hostname as the bare hostname", () => {
    // http://localhost./ resolves to loopback but matched neither PRIVATE_HOSTNAMES nor
    // the .internal/.local suffixes, so it was classified public.
    expect(normalizeHostname("LOCALHOST.")).toBe("localhost");
    expect(extractHostname("http://localhost./")).toBe("localhost");
    expect(isPrivateHostname("localhost.")).toBe(true);
    expect(isPrivateHostname("svc.internal.")).toBe(true);

    const result = inspectNetworkRequest(
      { url: "http://localhost./secret" },
      { defaultDeny: false, allowedSchemes: ["http"], allowedPorts: [80] }
    );
    expect(result.allowed).toBe(false);
    expect(result.ssrf).toBe(true);
    expect(result.blockedCategory).toBe("private-target");
  });

  it("never normalises a hostname down to the empty string", () => {
    // An empty hostname is the one value the defaultDeny guard skips, so "." must stay ".".
    expect(normalizeHostname(".")).toBe(".");
    expect(normalizeHostname("..")).toBe("..");
    expect(inspectNetworkRequest({ url: "http://./" }).allowed).toBe(false);
  });

  for (const url of [
    "http://[::1]/",
    "http://[0:0:0:0:0:0:0:1]/",
    "http://[fd00::1]/",
    "http://[fe80::1]/",
    "http://[::]/",
    "http://[::ffff:127.0.0.1]/",
    "https://[fc00::1]/v1/keys",
  ]) {
    it(`blocks ${url} as a private target`, () => {
      const result = inspectNetworkRequest({ url });
      expect(result.allowed).toBe(false);
      expect(result.ssrf).toBe(true);
      expect(result.privateRange).toBe(true);
      expect(result.blockedCategory).toBe("private-target");
      expect(result.riskLevel).toBe("critical");
    });
  }

  it("blocks the ip6 loopback hostnames", () => {
    for (const url of ["http://ip6-localhost/", "http://ip6-loopback:9200/"]) {
      const result = inspectNetworkRequest({ url });
      expect(result.allowed).toBe(false);
      expect(result.ssrf).toBe(true);
    }
  });

  it("does not flag a public IPv6 address as private", () => {
    const result = inspectNetworkRequest({ url: "https://[2606:4700:4700::1111]/dns-query" });
    expect(result.privateRange).toBe(false);
    expect(result.ssrf).toBe(false);
    expect(result.blockedCategory).toBe("default-deny-egress");
  });

  it("allows a public IPv6 host allowlisted in either bracket style", () => {
    for (const entry of ["2606:4700:4700::1111", "[2606:4700:4700::1111]"]) {
      const result = inspectNetworkRequest(
        { url: "https://[2606:4700:4700::1111]/dns-query" },
        { allowedHosts: [entry] }
      );
      expect(result.allowed).toBe(true);
      expect(result.privateRange).toBe(false);
    }
  });

  it("keeps allowlisting insufficient for private IPv6 targets", () => {
    const url = "https://[fd00::1]/";
    expect(inspectNetworkRequest({ url }, { allowedHosts: ["fd00::1"] }).allowed).toBe(false);

    const permitted = inspectNetworkRequest(
      { url },
      { allowPrivateRanges: true, allowedHosts: ["[fd00::1]"] }
    );
    expect(permitted.allowed).toBe(true);
    expect(permitted.privateRange).toBe(true);
  });
});
