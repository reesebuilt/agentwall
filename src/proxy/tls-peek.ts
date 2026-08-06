import { isPlausibleHostname } from "./hostname";

/**
 * ClientHello reading: the destination a TLS client actually asked for.
 *
 * This is NOT interception. Nothing here decrypts, terminates, or rewrites anything. The
 * ClientHello is the first plaintext record of a TLS connection, sent before any key
 * exchange completes, and SNI is a hostname the client puts on the wire in the clear so the
 * server knows which certificate to present. Reading it costs no CA, no trust-store change,
 * and no ability to see one byte of the session that follows.
 *
 * Two callers, two different jobs:
 *
 *   - The transparent listener has no other statement of destination, so SNI is how a
 *     redirected TLS connection gets named at all. No name, no connection.
 *   - The forward proxy already has a destination, but only because the client supplied it
 *     on the `CONNECT` line. SNI is a second, independent statement of the same fact from a
 *     different layer, and the two disagreeing is a signal in its own right: a client that
 *     names an allowlisted host to the proxy and then negotiates a different one has
 *     described a bypass. See `forward-proxy.ts` for what is done about it.
 *
 * WHAT THIS CANNOT DO, stated here so no caller has to infer it: SNI names a host and
 * nothing else. There is no port, no path, no header and no body in it. Encrypted ClientHello
 * removes even the host, and a client that omits the extension never had one to read. A name
 * recovered here is a strictly better-sourced hostname, not a window into the session.
 */

const TLS_HANDSHAKE = 0x16;
const HANDSHAKE_CLIENT_HELLO = 0x01;
const TLS_RECORD_HEADER_BYTES = 5;
const EXT_SERVER_NAME = 0x0000;
const SNI_HOST_NAME = 0x00;

/**
 * The largest first record worth buffering: a maximal TLS record plus its header.
 *
 * A caller reading a ClientHello off a live socket needs a stopping condition, and the
 * protocol supplies an exact one rather than a guess. Sizing it to the maximum means no
 * legitimate hello is ever cut short, which matters more than it used to: post-quantum key
 * shares pushed typical hello sizes past a single ethernet frame, so the fragmented case
 * this bounds is ordinary traffic now rather than a curiosity.
 */
export const MAX_CLIENT_HELLO_BYTES = TLS_RECORD_HEADER_BYTES + 16384;

/**
 * What a partial read of a connection's first bytes has established so far.
 *
 * The three cases exist because a caller reading from a socket has to distinguish "this will
 * never be a ClientHello" from "this is not a ClientHello yet". `extractSni` alone cannot:
 * it answers null to both, and a caller that treated null as final would give up on a
 * fragmented hello, while one that treated it as provisional would stall every plain-TCP
 * tunnel until its timeout expired.
 */
export type ClientHelloPeek =
  /** The first byte is not a TLS handshake record. Nothing here will ever be a hello. */
  | { status: "not-tls" }
  /** Consistent with a hello so far, but the first record is not all here yet. */
  | { status: "incomplete" }
  /** The first record is complete and has been parsed. `sni` is null if it carried no usable name. */
  | { status: "complete"; sni: string | null };

/**
 * Classify the bytes read from a connection so far, without waiting for more than needed.
 *
 * Completeness is decided from the record's own declared length, which is the only honest
 * source for it: five bytes in, the record says how long it is, so "have I got all of it"
 * stops being a heuristic. That is what lets a caller stop reading the instant the hello is
 * whole, including when it is whole and carries no SNI at all. Waiting out a timeout on that
 * case would add seconds of latency to every TLS connection from a client that omits the
 * extension, which is a real class of client and not a broken one.
 *
 * A zero-length record is reported complete with no name rather than incomplete: it is
 * malformed, and no quantity of further bytes can make a record that declared itself empty
 * into a valid hello. Reporting it incomplete would hang the caller until its timeout for
 * no possible gain.
 */
export function peekClientHello(buf: Buffer): ClientHelloPeek {
  if (buf.length === 0) return { status: "incomplete" };
  // Decided on the very first byte, before any length is trusted, so a plain-TCP tunnel
  // through the forward proxy is released immediately instead of buffering toward a
  // handshake that is never coming.
  if (buf[0] !== TLS_HANDSHAKE) return { status: "not-tls" };
  if (buf.length < TLS_RECORD_HEADER_BYTES) return { status: "incomplete" };

  const recordLength = buf.readUInt16BE(3);
  if (recordLength === 0) return { status: "complete", sni: null };
  if (buf.length < TLS_RECORD_HEADER_BYTES + recordLength) return { status: "incomplete" };

  return { status: "complete", sni: extractSni(buf) };
}

/**
 * Pull the SNI host_name out of a TLS ClientHello, or return null.
 *
 * Null means "no usable name here" and never means "probably fine": a truncated record, a
 * non-TLS first byte, a length field that overruns its container, an absent extension and a
 * name that fails validation all return null. What a caller does about that differs by
 * caller, which is why this function does not decide it: the transparent listener denies,
 * the forward proxy keeps the destination the CONNECT line already gave it. Truncation is
 * the one ambiguous case, and `peekClientHello` is what separates it from the rest.
 *
 * EVERY read is bounds-checked against the enclosing structure's end before it happens, and
 * each nested length is checked against its parent's rather than against the buffer, so a
 * declared length cannot walk the cursor past the record it lives in. This function is
 * handed the first packet of a connection from an untrusted process; an out-of-range read
 * here is not a wrong answer, it is a thrown exception in a component with nothing behind it.
 */
export function extractSni(clientHello: Buffer): string | null {
  if (clientHello.length < TLS_RECORD_HEADER_BYTES) return null;
  if (clientHello[0] !== TLS_HANDSHAKE) return null;

  const recordLength = clientHello.readUInt16BE(3);
  const recordEnd = TLS_RECORD_HEADER_BYTES + recordLength;
  // Require the whole record. A partial record cannot be distinguished from a malformed one
  // without guessing, and this parser does not guess.
  if (recordLength === 0 || clientHello.length < recordEnd) return null;

  let p = TLS_RECORD_HEADER_BYTES;

  // Handshake header: type (1) + length (3).
  if (p + 4 > recordEnd) return null;
  if (clientHello[p] !== HANDSHAKE_CLIENT_HELLO) return null;
  const handshakeLength = clientHello.readUIntBE(p + 1, 3);
  p += 4;
  const bodyEnd = p + handshakeLength;
  if (bodyEnd > recordEnd) return null;

  // client_version (2) + random (32).
  if (p + 34 > bodyEnd) return null;
  p += 34;

  // session_id.
  if (p + 1 > bodyEnd) return null;
  const sessionIdLength = clientHello[p];
  p += 1;
  if (p + sessionIdLength > bodyEnd) return null;
  p += sessionIdLength;

  // cipher_suites.
  if (p + 2 > bodyEnd) return null;
  const cipherSuitesLength = clientHello.readUInt16BE(p);
  p += 2;
  if (p + cipherSuitesLength > bodyEnd) return null;
  p += cipherSuitesLength;

  // compression_methods.
  if (p + 1 > bodyEnd) return null;
  const compressionLength = clientHello[p];
  p += 1;
  if (p + compressionLength > bodyEnd) return null;
  p += compressionLength;

  // extensions block. Absent entirely on an SSLv3-era hello, which has no SNI to find.
  if (p + 2 > bodyEnd) return null;
  const extensionsLength = clientHello.readUInt16BE(p);
  p += 2;
  const extensionsEnd = p + extensionsLength;
  if (extensionsEnd > bodyEnd) return null;

  while (p + 4 <= extensionsEnd) {
    const extensionType = clientHello.readUInt16BE(p);
    const extensionLength = clientHello.readUInt16BE(p + 2);
    p += 4;
    // An extension claiming more bytes than the block holds is malformed, not merely
    // uninteresting: continuing past it would mean parsing whatever follows as an extension
    // header. Refuse the whole hello.
    if (p + extensionLength > extensionsEnd) return null;
    if (extensionType === EXT_SERVER_NAME) {
      return parseServerNameList(clientHello, p, p + extensionLength);
    }
    p += extensionLength;
  }
  return null;
}

function parseServerNameList(buf: Buffer, start: number, end: number): string | null {
  let p = start;
  if (p + 2 > end) return null;
  const listLength = buf.readUInt16BE(p);
  p += 2;
  const listEnd = p + listLength;
  if (listEnd > end) return null;

  while (p + 3 <= listEnd) {
    const nameType = buf[p];
    const nameLength = buf.readUInt16BE(p + 1);
    p += 3;
    if (p + nameLength > listEnd) return null;
    if (nameType === SNI_HOST_NAME) {
      // latin1, not utf8: a byte outside ASCII must survive as a character the validator
      // rejects. Decoding as utf8 would turn invalid sequences into U+FFFD, which is a
      // printable character that could sail through a naive charset check.
      const name = buf.toString("latin1", p, p + nameLength);
      return isPlausibleHostname(name) ? name.toLowerCase() : null;
    }
    p += nameLength;
  }
  return null;
}
