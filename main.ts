/**
 * passion8 relay - Claude 1h full-prefix cache + current-time injection + response diagnostics
 * Single-file version for Zeabur (v3.1: reverse-proxy-safe HTTPS detection)
 * Upstream: https://passion8.cc
 *
 * LobeHub Anthropic Base URL:
 * https://YOUR_PROJECT.zeabur.app
 * Do not use http:// and do not append /v1/messages to the Base URL.
 *
 * v3.1 fix:
 * - Trusts x-forwarded-proto when present, avoiding an HTTPS redirect loop behind Zeabur.
 *
 * v3 changes:
 * - Redirects HTTP to HTTPS with status 308 so POST and its body are preserved.
 * - Rejects GET /v1/messages and GET /v1/chat/completions locally with a clear 405.
 * - Canonicalizes /messages and /chat/completions aliases to their /v1 upstream paths.
 * - Keeps all v2 non-stream/SSE, cache, time injection and diagnostics behavior.
 *
 * v2 changes (fix: upstream streaming path rejecting message-level ttl:"1h"):
 * - FORCE_NON_STREAM=1 (default on): rewrites incoming stream=true requests to
 *   stream=false before forwarding upstream (non-stream + 1h cache works, proven),
 *   then converts the full JSON response back into an SSE event stream so LobeHub
 *   renders normally. Set FORCE_NON_STREAM=0 to restore passthrough streaming.
 *
 * Default behavior:
 * 1. Removes LobeHub's built-in 5m breakpoints, places a single 1h breakpoint on
 *    the last message (it caches all preceding tools/system/messages).
 * 2. Appends current time after the cache breakpoint of the last user message
 *    (the time block itself is never cached).
 * 3. Each incoming request triggers exactly 1 upstream request, no auto retry.
 * 4. /logs shows breakpoints, cache usage, raw failures and request ids.
 *
 * Optional env vars:
 * UPSTREAM_URL        default https://passion8.cc
 * PROXY_TOKEN         optional access token; requests must carry x-proxy-token
 * CACHE_TTL_ON        "0" = do not touch cache; default on
 * BREAKPOINT_MODE     "message" (default, single message breakpoint) | "all" (max 4)
 * TAIL_BREAKPOINTS    number of tail message breakpoints; default 2, suggest 1~2
 * INJECT_CURRENT_TIME "0" = do not inject current time; default on
 * TIME_ZONE           default Asia/Shanghai
 * DEBUG               "1" = print detailed logs for successful requests too
 * FORCE_NON_STREAM    "0" = passthrough streaming (may hit upstream 502); default force non-stream + SSE
 * FORCE_HTTPS          "0" = disable production HTTP->HTTPS 308 redirect; default on
 * PORT                listen port; default 8000 (Zeabur injects PORT for some service types)
 */

const PROVIDER = "passion8";
const VERSION = "v3.4.4-errraw";
const DEFAULT_UPSTREAM = "https://passion8.cc";
const TTL = "1h";
const BETA_FLAG = "extended-cache-ttl-2025-04-11";
const MAX_BREAKPOINTS = 4;
const MIN_CHARS = 2000;
const RUNTIME_MARKER = "pxy8-proxy-runtime-time-v1";

// deno-lint-ignore no-explicit-any
type Any = any;

const UPSTREAM = (Deno.env.get("UPSTREAM_URL") || DEFAULT_UPSTREAM).replace(/\/+$/, "");
const PROXY_TOKEN = Deno.env.get("PROXY_TOKEN") || "";
const CACHE_ENABLED = Deno.env.get("CACHE_TTL_ON") !== "0";
const BREAKPOINT_MODE = (Deno.env.get("BREAKPOINT_MODE") || "message").toLowerCase();
const TIME_ENABLED = Deno.env.get("INJECT_CURRENT_TIME") !== "0";
const TIME_ZONE = Deno.env.get("TIME_ZONE") || "Asia/Shanghai";
const DEBUG = Deno.env.get("DEBUG") === "1";
const LOG_BODY = Deno.env.get("LOG_BODY") !== "0"; // default ON; LOG_BODY=0 disables
const FORCE_NON_STREAM = Deno.env.get("FORCE_NON_STREAM") !== "0";
const STREAM_UPSTREAM = Deno.env.get("STREAM_UPSTREAM") !== "0";
const FORCE_HTTPS = Deno.env.get("FORCE_HTTPS") !== "0";
const PORT = Number(Deno.env.get("PORT") || 8000);

const parsedTail = Number(Deno.env.get("TAIL_BREAKPOINTS") ?? "2");
const TAIL_BREAKPOINTS = Number.isFinite(parsedTail)
  ? Math.max(0, Math.min(2, Math.trunc(parsedTail)))
  : 2;

const CACHEABLE_TYPES = new Set([
  "text",
  "image",
  "document",
  "tool_use",
  "tool_result",
  "search_result",
]);

const CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers":
    "content-type, x-proxy-token, authorization, x-api-key, anthropic-version, anthropic-beta, anthropic-dangerous-direct-browser-access",
  "access-control-expose-headers": "x-proxy-request-id",
  "access-control-max-age": "86400",
};

const STRIP_HEADERS = [
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "keep-alive",
  "upgrade",
  "expect",
  "accept-encoding",
  "x-proxy-token",
  "x-proxy-request-id",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
];

const LOG_LINES: string[] = [];
let sequence = 0;

function isObj(v: unknown): v is Record<string, Any> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function json(data: unknown, status = 200, requestId = ""): Response {
  const headers = new Headers({
    ...CORS_HEADERS,
    "content-type": "application/json; charset=utf-8",
  });
  if (requestId) headers.set("x-proxy-request-id", requestId);
  return new Response(JSON.stringify(data), { status, headers });
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function normalizePath(pathname: string): string {
  return pathname.replace(/\/+$/, "") || "/";
}

function isMessagesPath(path: string): boolean {
  return path === "/v1/messages" || path === "/messages";
}

function isChatPath(path: string): boolean {
  return path === "/v1/chat/completions" || path === "/chat/completions";
}

function canonicalUpstreamPath(path: string): string {
  if (isMessagesPath(path)) return "/v1/messages";
  if (isChatPath(path)) return "/v1/chat/completions";
  return path;
}

function isLocalHostname(hostname: string): boolean {
  const value = hostname.toLowerCase();
  return value === "localhost" || value === "127.0.0.1" || value === "::1";
}

function resolveUpstream(path: string): string {
  return UPSTREAM + canonicalUpstreamPath(path);
}

function formatTime(date = new Date(), includeSeconds = false): string {
  try {
    const options: Intl.DateTimeFormatOptions = {
      timeZone: TIME_ZONE,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    };
    if (includeSeconds) options.second = "2-digit";
    return new Intl.DateTimeFormat("sv-SE", options).format(date);
  } catch {
    return date.toISOString();
  }
}

function clock(): string {
  return formatTime(new Date(), true).replace("T", " ");
}

function record(line: string, _forceConsole = false): void {
  LOG_LINES.push(line);
  if (LOG_LINES.length > 1000) LOG_LINES.shift();
  // Always emit to stdout: Zeabur Runtime Logs persist every request
  // (memory /logs is a restart-wiped mirror of the same lines).
  console.log(line);
}

function shortHash(v: unknown): string {
  let s: string;
  try {
    s = typeof v === "string" ? v : JSON.stringify(v ?? null);
  } catch {
    s = String(v);
  }
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  }
  return `${(h >>> 0).toString(16).padStart(8, "0")}/${s.length}`;
}

/**
 * Diagnostic hash ignores cache_control and the proxy time block,
 * so different hashes between two logs mean the real prompt changed.
 */
function diagnosticValue(v: unknown): unknown {
  if (Array.isArray(v)) {
    return v
      .filter((item) => !(
        isObj(item) &&
        item.type === "text" &&
        typeof item.text === "string" &&
        item.text.includes(RUNTIME_MARKER)
      ))
      .map(diagnosticValue);
  }
  if (!isObj(v)) return v;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(v)) {
    if (key === "cache_control") continue;
    out[key] = diagnosticValue(value);
  }
  return out;
}

function diagnosticHash(v: unknown): string {
  return shortHash(diagnosticValue(v));
}

function messageHashes(body: Any): string {
  if (!Array.isArray(body?.messages)) return "-";
  return body.messages.map((msg: unknown, index: number) => {
    if (!isObj(msg)) return `${index}?:invalid`;
    const role = String(msg.role ?? "?").slice(0, 1);
    return `${index}${role}:${diagnosticHash(msg.content)}`;
  }).join(",");
}

function cc() {
  return { type: "ephemeral", ttl: TTL };
}

function approxChars(body: Any): number {
  let n = 0;
  const walk = (v: unknown) => {
    if (typeof v === "string") {
      n += v.length;
    } else if (Array.isArray(v)) {
      for (const x of v) walk(x);
    } else if (isObj(v)) {
      for (const x of Object.values(v)) walk(x);
    }
  };
  walk(body?.system);
  walk(body?.messages);
  walk(body?.tools);
  return n;
}

function existingHolders(body: Any): Record<string, Any>[] {
  const out: Record<string, Any>[] = [];
  const walk = (v: unknown) => {
    if (Array.isArray(v)) {
      for (const x of v) walk(x);
      return;
    }
    if (!isObj(v)) return;
    if (isObj(v.cache_control)) out.push(v);
    for (const x of Object.values(v)) walk(x);
  };
  walk(body?.system);
  walk(body?.messages);
  walk(body?.tools);
  return out;
}

function toBlocks(v: unknown): Record<string, Any>[] | null {
  if (typeof v === "string") {
    return v.trim() === "" ? null : [{ type: "text", text: v }];
  }
  if (Array.isArray(v)) {
    const blocks = v.filter(isObj);
    return blocks.length > 0 ? blocks : null;
  }
  return null;
}

function lastCacheable(blocks: Record<string, Any>[]): Record<string, Any> | null {
  for (let i = blocks.length - 1; i >= 0; i--) {
    const type = blocks[i].type;
    if (typeof type === "string" && CACHEABLE_TYPES.has(type)) return blocks[i];
  }
  return null;
}

/**
 * Remove a previously injected runtime time block if some client saved it into
 * history. Normal LobeHub does not save rewritten requests; this is defensive.
 */
function removeOldRuntimeBlocks(body: Any): number {
  if (!Array.isArray(body?.messages)) return 0;
  let removed = 0;
  for (const msg of body.messages) {
    if (!isObj(msg) || !Array.isArray(msg.content)) continue;
    const before = msg.content.length;
    msg.content = msg.content.filter((block: unknown) => {
      return !(
        isObj(block) &&
        block.type === "text" &&
        typeof block.text === "string" &&
        block.text.includes(RUNTIME_MARKER)
      );
    });
    removed += before - msg.content.length;
  }
  return removed;
}

interface InjectResult {
  changed: boolean;
  applied: string[];
  skipped?: string;
}

/**
 * Single message breakpoint mode.
 * Removes LobeHub's 5m breakpoints (avoid mixing old 5m parent cache with the
 * new 1h delta), then places the single 1h breakpoint on the last cacheable
 * block of the newest message.
 */
function injectAnthropicMessage(body: Any): InjectResult {
  const holders = existingHolders(body);
  for (const holder of holders) delete holder.cache_control;

  const applied: string[] = [];
  let changed = holders.length > 0;
  if (holders.length > 0) applied.push(`removed:${holders.length}`);

  const chars = approxChars(body);
  if (chars < MIN_CHARS) {
    return { changed, applied, skipped: `too-small:${chars}<${MIN_CHARS}` };
  }
  if (!Array.isArray(body?.messages) || body.messages.length === 0) {
    return { changed, applied, skipped: "no-messages" };
  }

  for (let i = body.messages.length - 1; i >= 0; i--) {
    const msg = body.messages[i];
    if (!isObj(msg)) continue;
    const blocks = toBlocks(msg.content);
    const target = blocks && lastCacheable(blocks);
    if (!blocks || !target) continue;
    msg.content = blocks;
    target.cache_control = cc();
    applied.push(`msg[${i}]:${msg.role ?? "?"}`);
    changed = true;
    return { changed, applied };
  }

  return { changed, applied, skipped: "no-cacheable-message-block" };
}

/**
 * Multi breakpoint compatibility mode: keep LobeHub's existing breakpoints and
 * upgrade all of them to 1h, then top up tools -> system -> tail messages,
 * up to 4 breakpoints.
 */
function injectAnthropicAll(body: Any, tailBreakpoints: number): InjectResult {
  const applied: string[] = [];
  let changed = false;

  const holders = existingHolders(body);
  for (const holder of holders) {
    const old = holder.cache_control;
    if (old?.type !== "ephemeral" || old?.ttl !== TTL) {
      holder.cache_control = cc();
      changed = true;
    }
  }
  if (holders.length > 0) applied.push(`upgraded:${holders.length}`);

  const chars = approxChars(body);
  if (chars < MIN_CHARS) {
    return { changed, applied, skipped: `too-small:${chars}<${MIN_CHARS}` };
  }

  let budget = MAX_BREAKPOINTS - holders.length;
  if (budget <= 0) {
    return { changed, applied, skipped: holders.length > MAX_BREAKPOINTS ? "too-many-existing-breakpoints" : "no-budget" };
  }

  const mark = (holder: Record<string, Any>, label: string) => {
    holder.cache_control = cc();
    applied.push(label);
    budget--;
    changed = true;
  };

  if (budget > 0 && Array.isArray(body.tools) && body.tools.length > 0) {
    const tool = body.tools.filter(isObj).at(-1);
    if (tool && !isObj(tool.cache_control)) mark(tool, "tools");
  }

  if (budget > 0 && body.system !== undefined) {
    const blocks = toBlocks(body.system);
    const target = blocks && lastCacheable(blocks);
    if (blocks && target && !isObj(target.cache_control)) {
      body.system = blocks;
      mark(target, "system");
    }
  }

  if (budget > 0 && tailBreakpoints > 0 && Array.isArray(body.messages)) {
    let placed = 0;
    for (
      let i = body.messages.length - 1;
      i >= 0 && placed < tailBreakpoints && budget > 0;
      i--
    ) {
      const msg = body.messages[i];
      if (!isObj(msg)) continue;
      const blocks = toBlocks(msg.content);
      const target = blocks && lastCacheable(blocks);
      if (!blocks || !target || isObj(target.cache_control)) continue;
      msg.content = blocks;
      mark(target, `msg[${i}]:${msg.role ?? "?"}`);
      placed++;
    }
  }

  return { changed, applied };
}

function injectOpenAI(body: Any): InjectResult {
  const applied: string[] = [];
  let changed = false;

  const holders = existingHolders(body);
  for (const holder of holders) {
    const old = holder.cache_control;
    if (old?.type !== "ephemeral" || old?.ttl !== TTL) {
      holder.cache_control = cc();
      changed = true;
    }
  }
  if (holders.length > 0) applied.push(`upgraded:${holders.length}`);

  if (approxChars(body) < MIN_CHARS) {
    return { changed, applied, skipped: "too-small" };
  }
  if (!Array.isArray(body.messages)) {
    return { changed, applied, skipped: "no-messages" };
  }

  for (const msg of body.messages) {
    if (!isObj(msg) || msg.role !== "system") continue;
    if (Array.isArray(msg.content)) {
      const target = lastCacheable(msg.content.filter(isObj));
      if (target && !isObj(target.cache_control)) {
        target.cache_control = cc();
        applied.push("system-block");
        changed = true;
      }
    } else if (typeof msg.content === "string" && !isObj(msg.cache_control)) {
      msg.cache_control = cc();
      applied.push("system-message");
      changed = true;
    }
  }

  return { changed, applied };
}

/**
 * Must be called after injectAnthropic(). The new time block sits after the
 * newest cache breakpoint and never carries cache_control itself.
 */
function appendCurrentTime(body: Any): { added: boolean; reason?: string } {
  if (!Array.isArray(body?.messages) || body.messages.length === 0) {
    return { added: false, reason: "no-messages" };
  }

  const last = body.messages.at(-1);
  if (!isObj(last) || last.role !== "user") {
    return { added: false, reason: "last-not-user" };
  }

  if (typeof last.content === "string") {
    last.content = [{ type: "text", text: last.content }];
  }
  if (!Array.isArray(last.content)) {
    return { added: false, reason: "unsupported-content" };
  }

  const now = new Date();
  last.content.push({
    type: "text",
    text:
      `<!-- ${RUNTIME_MARKER} -->\n` +
      `<runtime_context source="request_proxy">\n` +
      `Current time: ${formatTime(now)}\n` +
      `Time zone: ${TIME_ZONE}\n` +
      `This is runtime info added by the proxy, not the user's original text. ` +
      `Only use it when the question involves now, today, dates, deadlines or relative time.\n` +
      `</runtime_context>`,
  });
  return { added: true };
}

function mergeBetaHeader(current: string | null): string {
  const parts = (current ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!parts.includes(BETA_FLAG)) parts.push(BETA_FLAG);
  return parts.join(",");
}

function scanBreakpoints(body: Any): string {
  const found: string[] = [];
  const ttlOf = (v: unknown): string | null => {
    if (!isObj(v) || !isObj(v.cache_control)) return null;
    return String(v.cache_control.ttl ?? "5m");
  };

  if (Array.isArray(body?.tools)) {
    body.tools.forEach((tool: unknown, i: number) => {
      const ttl = ttlOf(tool);
      if (ttl) found.push(`tool${i}:${ttl}`);
    });
  }
  if (Array.isArray(body?.system)) {
    body.system.forEach((block: unknown, i: number) => {
      const ttl = ttlOf(block);
      if (ttl) found.push(`sys${i}:${ttl}`);
    });
  }
  if (Array.isArray(body?.messages)) {
    body.messages.forEach((msg: unknown, i: number) => {
      if (!isObj(msg) || !Array.isArray(msg.content)) return;
      msg.content.forEach((block: unknown, j: number) => {
        const ttl = ttlOf(block);
        if (ttl) found.push(`msg${i}.${j}:${ttl}`);
      });
    });
  }

  return found.length === 0 ? "none" : `${found.length}[${found.join(",")}]`;
}

function rolesOf(body: Any): string {
  if (!Array.isArray(body?.messages)) return "-";
  return body.messages.map((msg: unknown) => {
    if (!isObj(msg)) return "?";
    return String(msg.role ?? "?").slice(0, 1);
  }).join("");
}

function responseHeaders(source: Headers, requestId: string): Headers {
  const out = new Headers(source);
  out.delete("content-encoding");
  out.delete("content-length");
  out.delete("transfer-encoding");
  out.delete("connection");
  for (const [key, value] of Object.entries(CORS_HEADERS)) out.set(key, value);
  out.set("x-proxy-request-id", requestId);
  return out;
}

function readUsage(text: string, key: string): string {
  const pattern = new RegExp(`"${key}"\\s*:\\s*(\\d+)`, "g");
  let value = "-";
  for (const match of text.matchAll(pattern)) value = match[1];
  return value;
}

/** 验水指纹：从上游响应体提取思考/签名/空完成证据。 */
/** 解码 Anthropic 思考签名中的模型标识（官方签名内置模型名，防伪）。 */
function sigModelOf(text: string): string {
  const m = text.match(/"signature"\s*:\s*"([^"]+)"/);
  if (!m) return "-";
  const sig = m[1];
  try {
    const bin = atob(sig);
    const mm = bin.match(/claude-[a-z0-9-]+/i);
    if (mm) return mm[0];
  } catch {
    // 非标准 base64 或截断，忽略
  }
  return `raw:${sig.slice(0, 24)}...`;
}

function probeResponse(text: string): string {
  const hasThinking = text.includes('"type":"thinking"') || text.includes('"type": "thinking"') || text.includes('"reasoning"');
  const hasSignature = text.includes('"signature"');
  const thinkTok = readUsage(text, "thinking_tokens") !== "-"
    ? readUsage(text, "thinking_tokens")
    : readUsage(text, "reasoning_tokens");
  const hasEmpty = text.includes('"content":[]') && text.includes('"stop_reason":"end_turn"');
  const parts = [`think=${hasThinking ? "Y" : "N"}`, `sig=${hasSignature ? "Y" : "N"}`, `sigModel=${sigModelOf(text)}`];
  if (thinkTok !== "-") parts.push(`thinkTok=${thinkTok}`);
  if (hasEmpty) parts.push(`EMPTY=YES`);
  return parts.join(" ");
}

interface ForwardMeta {
  id: string;
  head: string;
  path: string;
  convertSse?: boolean;
  streamUpstream?: boolean;
}

function sseFrame(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}`;
}

/**
 * STREAM_UPSTREAM 模式：向上游发 stream=true 真流式，把上游 SSE 流标准化后转发给客户端。
 * - thinking_delta 明文原样透传（New API 网关在非流式下会剥离 thinking 字段，流式下可能返回）
 * - 防空完成防护：去重 message_start/message_stop、忽略坏帧、流中断时补发 message_stop
 */
function parseSseFrame(frame: string): { event: string; data: string } | null {
  let event = "message";
  const dataLines: string[] = [];
  for (const line of frame.split(/\r?\n/)) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).replace(/^ /, ""));
  }
  if (dataLines.length === 0) return null;
  return { event, data: dataLines.join("\n") };
}

async function streamForward(
  upstream: Response,
  meta: ForwardMeta,
  elapsed: number,
): Promise<Response> {
  const started = performance.now();
  const out = responseHeaders(upstream.headers, meta.id);
  out.set("content-type", "text/event-stream; charset=utf-8");
  out.set("cache-control", "no-cache");
  if (upstream.status !== 200) {
    // 非 200：读完整 body 记录 RAW 到日志，并转 error SSE 给客户端
    let text = "";
    try { text = await new Response(upstream.body).text(); } catch { /* ignore */ }
    const errMs = Math.round(performance.now() - started);
    record(`${meta.head}\n  attempt=1 status=${upstream.status} ms=${errMs} len=${text.length} ERR-BODY <${text.slice(0, 4000).replace(/\s+/g, " ")}>`, true);
    const ev = `event: error\ndata: ${JSON.stringify({ type: "error", error: { type: "upstream_error", message: text.slice(0, 300) } })}\n\n`;
    const finish = `event: message_stop\ndata: {"type":"message_stop"}\n\n`;
    return new Response(new TextEncoder().encode(ev + finish), { status: upstream.status, headers: out });
  }

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let buffer = "";
  let closed = false;
  let sawFirst = false;
  let sawStop = false;
  let pendingStop = false;
  const thinkParts: string[] = [];
  const textParts: string[] = [];
  let sigCount = 0;
  let firstSig = "";
  let usageJson = "";
  const frameCount = { n: 0 };

  const finishFrame = 'event: message_stop\ndata: {"type":"message_stop"}';

  const readable = new ReadableStream<Uint8Array>({
    async start(controller) {
      const push = (s: string): void => {
        if (!closed) controller.enqueue(encoder.encode(s + "\n\n"));
      };
      const logMeta = () => {
        const thinkText = thinkParts.join("");
        const text = textParts.join("");
        const usage = [
          `attempt=1`,
          `status=${upstream.status}`,
          `ms=${elapsed}`,
          `len=${(thinkText + text).length}`,
          `read=${readUsage(usageJson, "cache_read_input_tokens")}`,
          `create=${readUsage(usageJson, "cache_creation_input_tokens")}`,
          `w1h=${readUsage(usageJson, "ephemeral_1h_input_tokens")}`,
          `w5m=${readUsage(usageJson, "ephemeral_5m_input_tokens")}`,
          `in=${readUsage(usageJson, "input_tokens")}`,
          `out=${readUsage(usageJson, "output_tokens")}`,
        ].join(" ");
        const thinkTok = readUsage(usageJson, "thinking_tokens");
        const probeParts = [
          `think=${thinkParts.length > 0 ? "Y" : "N"}`,
          `sig=${sigCount > 0 ? "Y" : "N"}`,
          `sigModel=${firstSig ? sigModelOf(JSON.stringify({ signature: firstSig })) : "-"}`,
          `thinkTok=${thinkTok !== "-" ? thinkTok : (thinkParts.length > 0 ? String(Math.max(1, Math.round(thinkText.length / 4))) : "-")}`,
          `thinkLen=${thinkText.length}`,
          `frames=${frameCount.n}`,
        ].join(" ");
        record(`${meta.head}\n  ${usage} probe=${probeParts} mode=stream`, !upstream.ok);
      };
      const finish = () => {
        if (closed) return;
        if (!sawStop) push(finishFrame);
        closed = true;
        try { controller.close(); } catch { /* ignore */ }
        try { logMeta(); } catch { /* ignore */ }
      };
      try {
        const reader = upstream.body?.getReader();
        if (!reader) { finish(); return; }
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let idx = buffer.indexOf("\n\n");
          while (idx >= 0) {
            const frame = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 2);
            idx = buffer.indexOf("\n\n");
            if (!frame.trim()) continue;
            const parsed = parseSseFrame(frame);
            if (!parsed) continue;
            let dataObj: Any;
            try { dataObj = JSON.parse(parsed.data); } catch { continue; }
            const type = dataObj?.type ?? parsed.event;
            if (type === "message_start") {
              if (sawFirst) continue; // 去重
              sawFirst = true;
              push("event: message_start\ndata: " + parsed.data);
            } else if (type === "content_block_start") {
              const cb = isObj(dataObj.content_block) ? dataObj.content_block : {};
              if (cb.type === "thinking" && typeof cb.signature === "string") {
                sigCount++;
                if (!firstSig) firstSig = cb.signature;
              }
              push("event: content_block_start\ndata: " + parsed.data);
            } else if (type === "content_block_delta") {
              const d = isObj(dataObj.delta) ? dataObj.delta : {};
              if (d.type === "thinking_delta" && typeof d.thinking === "string") thinkParts.push(d.thinking);
              if (d.type === "text_delta" && typeof d.text === "string") textParts.push(d.text);
              push("event: content_block_delta\ndata: " + parsed.data);
            } else if (type === "content_block_stop") {
              push("event: content_block_stop\ndata: " + parsed.data);
            } else if (type === "message_delta") {
              if (isObj(dataObj.usage)) usageJson = JSON.stringify(dataObj.usage);
              push("event: message_delta\ndata: " + parsed.data);
            } else if (type === "message_stop") {
              sawStop = true; // 不立即转发，确保总是最后一个事件
            } else if (type === "ping") {
              push("event: ping\ndata: " + parsed.data);
            } else if (type === "error") {
              push("event: error\ndata: " + parsed.data);
            }
            frameCount.n++;
          }
        }
        // 上游流结束：保证 message_stop 恰好一次、且为最后一个事件
        const tail = decoder.decode(); // 冲刷剩余字节
        if (tail) {
          buffer += tail;
          const idx = buffer.indexOf("\n\n");
          if (idx >= 0) {
            const frame = buffer.slice(0, idx);
            if (frame.trim()) {
              const parsed = parseSseFrame(frame);
              if (parsed) {
                try {
                  const dataObj = JSON.parse(parsed.data);
                  const type = dataObj?.type ?? parsed.event;
                  if (type !== "message_stop") {
                    push("event: content_block_stop\ndata: " + parsed.data);
                  } else {
                    sawStop = true;
                  }
                } catch { /* ignore */ }
              }
            }
          }
        }
        if (!sawStop) {
          // 上游没发 stop：补发（防止客户端空完成/挂起）
        }
        push(finishFrame);
        closed = true;
        try { controller.close(); } catch { /* ignore */ }
        try { logMeta(); } catch { /* ignore */ }
      } catch (error) {
        // 读流异常：不抛错，补终止事件
        try { finish(); } catch { /* ignore */ }
      }
    },
    cancel() {
      closed = true;
    },
  });

  return new Response(readable, { status: upstream.status, headers: out });
}

/**
 * Convert the upstream's full JSON (non-stream message response) into an
 * Anthropic SSE event stream. Supports text / thinking / tool_use blocks and
 * error objects.
 */
function toSse(text: string): string {
  let parsed: Any;
  try {
    parsed = JSON.parse(text);
  } catch {
    return `${sseFrame("error", { type: "error", error: { type: "parse_error", message: text.slice(0, 500) } })}\n\n`;
  }
  if (!isObj(parsed)) {
    return `${sseFrame("error", { type: "error", error: { type: "invalid_response", message: text.slice(0, 500) } })}\n\n`;
  }
  if (isObj(parsed.error)) {
    return `${sseFrame("error", { type: "error", error: parsed.error })}\n\n`;
  }

  const events: string[] = [];
  events.push(sseFrame("message_start", {
    type: "message_start",
    message: { ...parsed, content: [] },
  }));

  const blocks = Array.isArray(parsed.content) ? parsed.content : [];
  blocks.forEach((block: unknown, index: number) => {
    if (!isObj(block)) return;
    const start: Any = { type: "content_block_start", index, content_block: { ...block } };
    if (block.type === "text") start.content_block.text = "";
    if (block.type === "tool_use") start.content_block.input = undefined;
    events.push(sseFrame("content_block_start", start));

    if (block.type === "text" && typeof block.text === "string") {
      events.push(sseFrame("content_block_delta", {
        type: "content_block_delta",
        index,
        delta: { type: "text_delta", text: block.text },
      }));
    } else if (block.type === "thinking" && typeof block.thinking === "string") {
      events.push(sseFrame("content_block_delta", {
        type: "content_block_delta",
        index,
        delta: { type: "thinking_delta", thinking: block.thinking },
      }));
    } else if (block.type === "tool_use") {
      events.push(sseFrame("content_block_delta", {
        type: "content_block_delta",
        index,
        delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input ?? {}) },
      }));
    }

    events.push(sseFrame("content_block_stop", { type: "content_block_stop", index }));
  });

  events.push(sseFrame("message_delta", {
    type: "message_delta",
    delta: { stop_reason: parsed.stop_reason ?? null, stop_sequence: parsed.stop_sequence ?? null },
    usage: parsed.usage ?? {},
  }));
  events.push(sseFrame("message_stop", { type: "message_stop" }));
  return events.join("\n\n") + "\n\n";
}

/**
 * Exactly one fetch here: no loops, no backoff, no auto retry.
 * Option A: no AbortSignal is passed (dropped req.signal) to avoid Deno.serve
 * legacy behavior aborting the request signal after a successful response.
 * In convertSse mode: read full JSON -> convert to SSE -> respond to client.
 */
async function forwardOnce(
  method: string,
  target: string,
  headers: Headers,
  body: BodyInit | null,
  meta: ForwardMeta,
): Promise<Response> {
  let upstream: Response;
  const started = performance.now();
  try {
    upstream = await fetch(target, {
      method,
      headers,
      body,
      ...(body !== null && typeof body === "object" ? { duplex: "half" } : {}),
    } as RequestInit);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const line = `${meta.head}\n  attempt=1 FETCH-ERR ${message}`;
    record(line, true);
    return json({ error: `upstream error: ${message}` }, 502, meta.id);
  }

  const elapsed = Math.round(performance.now() - started);

  if (meta.streamUpstream) {
    return await streamForward(upstream, meta, elapsed);
  }

  if (meta.convertSse) {
    // Upstream was called with stream=false and returns full JSON; convert to SSE.
    let text = "";
    try {
      text = await new Response(upstream.body).text();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      record(`${meta.head}\n  attempt=1 convert-read-error=${message}`, true);
      return json({ error: `upstream read error: ${message}` }, 502, meta.id);
    }
    const input = readUsage(text, "input_tokens");
    const usage = [
      `attempt=1`,
      `status=${upstream.status}`,
      `ms=${elapsed}`,
      `len=${text.length}`,
      `read=${readUsage(text, "cache_read_input_tokens")}`,
      `create=${readUsage(text, "cache_creation_input_tokens")}`,
      `w1h=${readUsage(text, "ephemeral_1h_input_tokens")}`,
      `w5m=${readUsage(text, "ephemeral_5m_input_tokens")}`,
      `in=${input}`,
      `out=${readUsage(text, "output_tokens")}`,
    ].join(" ");
    const probe = probeResponse(text);
    const raw = !upstream.ok || input === "-"
      ? `\n  RAW ct=${upstream.headers.get("content-type") ?? "-"} <${text.slice(0, 600).replace(/\s+/g, " ")}>`
      : "";
    record(`${meta.head}\n  ${usage} probe=${probe}${raw}`, !upstream.ok);

    const out = responseHeaders(upstream.headers, meta.id);
    out.set("content-type", "text/event-stream; charset=utf-8");
    return new Response(toSse(text), { status: upstream.status, headers: out });
  }

  const out = responseHeaders(upstream.headers, meta.id);

  if (!upstream.body) {
    const line = `${meta.head}\n  attempt=1 status=${upstream.status} ms=${elapsed} no-body`;
    record(line, !upstream.ok);
    return new Response(null, { status: upstream.status, headers: out });
  }

  const [toClient, toLog] = upstream.body.tee();
  void (async () => {
    try {
      const text = await new Response(toLog).text();
      const input = readUsage(text, "input_tokens");
      const usage = [
        `attempt=1`,
        `status=${upstream.status}`,
        `ms=${elapsed}`,
        `len=${text.length}`,
        `read=${readUsage(text, "cache_read_input_tokens")}`,
        `create=${readUsage(text, "cache_creation_input_tokens")}`,
        `w1h=${readUsage(text, "ephemeral_1h_input_tokens")}`,
        `w5m=${readUsage(text, "ephemeral_5m_input_tokens")}`,
        `in=${input}`,
        `out=${readUsage(text, "output_tokens")}`,
      ].join(" ");

      const probe = probeResponse(text);

      const raw = !upstream.ok || input === "-"
        ? `\n  RAW ct=${upstream.headers.get("content-type") ?? "-"} <${
          text.slice(0, 600).replace(/\s+/g, " ")
        }>`
        : "";
      record(`${meta.head}\n  ${usage} probe=${probe}${raw}`, !upstream.ok);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      record(`${meta.head}\n  attempt=1 usage-log-error=${message}`, true);
    }
  })();

  return new Response(toClient, { status: upstream.status, headers: out });
}

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = normalizePath(url.pathname);

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (PROXY_TOKEN) {
    const supplied = req.headers.get("x-proxy-token") || url.searchParams.get("proxy_token") || "";
    if (!safeEqual(supplied, PROXY_TOKEN)) return json({ error: "unauthorized" }, 401);
  }
  // Allow viewing diagnostics via ?proxy_token=... in browser, never forward it upstream.
  url.searchParams.delete("proxy_token");

  // Use 308 rather than 301/302/303 so POST /v1/messages and its request body
  // remain POST when the client follows the HTTP -> HTTPS redirect.
  const forwardedProto = (req.headers.get("x-forwarded-proto") || "")
    .split(",")[0]
    .trim()
    .toLowerCase();
  // Behind Zeabur, req.url may use the internal http: hop even when the public
  // request was HTTPS. If x-forwarded-proto exists, it is authoritative.
  const arrivedOverHttp = forwardedProto
    ? forwardedProto === "http"
    : url.protocol === "http:";
  if (FORCE_HTTPS && arrivedOverHttp && !isLocalHostname(url.hostname)) {
    url.protocol = "https:";
    const headers = new Headers(CORS_HEADERS);
    headers.set("location", url.toString());
    headers.set("cache-control", "no-store");
    return new Response(null, { status: 308, headers });
  }

  if (req.method === "GET" && (path === "/" || path === "/health")) {
    return json({
      ok: true,
      provider: PROVIDER,
      version: VERSION,
      upstream: UPSTREAM,
      cache: CACHE_ENABLED ? `${TTL}/${BREAKPOINT_MODE}` : "passthrough",
      beta: CACHE_ENABLED ? BETA_FLAG : "not-added",
      tailBreakpoints: TAIL_BREAKPOINTS,
      currentTimeInjection: TIME_ENABLED,
      timeZone: TIME_ZONE,
      forceNonStream: FORCE_NON_STREAM,
      streamUpstream: STREAM_UPSTREAM,
      forceHttps: FORCE_HTTPS,
      upstreamAttemptsPerIncomingRequest: 1,
      logsInThisInstance: LOG_LINES.length,
    });
  }

  if (req.method === "GET" && path === "/logs") {
    return new Response(
      LOG_LINES.length === 0 ? "No logs yet." : LOG_LINES.join("\n\n"),
      { headers: { ...CORS_HEADERS, "content-type": "text/plain; charset=utf-8" } },
    );
  }

  if ((req.method === "GET" || req.method === "POST") && path === "/logs/clear") {
    LOG_LINES.length = 0;
    return new Response("Logs cleared.", {
      headers: { ...CORS_HEADERS, "content-type": "text/plain; charset=utf-8" },
    });
  }

  // Anthropic Messages and OpenAI Chat Completions are POST-only. Do not
  // passthrough an accidental GET to the upstream, where it becomes the vague
  // "Invalid URL (GET /v1/messages)" error.
  if ((isMessagesPath(path) || isChatPath(path)) && req.method !== "POST") {
    const headers = new Headers({
      ...CORS_HEADERS,
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "allow": "POST, OPTIONS",
    });
    return new Response(JSON.stringify({
      error: {
        message: `Method not allowed (${req.method} ${path}). Use an https:// Base URL; this endpoint requires POST.`,
        type: "invalid_request_error",
        param: "",
        code: "method_not_allowed",
      },
    }), { status: 405, headers });
  }

  const id = `${++sequence}-${crypto.randomUUID().slice(0, 8)}`;
  const target = resolveUpstream(path) + url.search;
  const headers = new Headers(req.headers);
  for (const header of STRIP_HEADERS) headers.delete(header);
  headers.set("x-proxy-request-id", id);

  const rewriteable = req.method === "POST" && (isMessagesPath(path) || isChatPath(path));
  if (!rewriteable) {
    const head = `#${id} ${clock()} path=${path} passthrough`;
    return await forwardOnce(req.method, target, headers, req.body, {
      id,
      head,
      path,
    });
  }

  let body: Any;
  try {
    body = JSON.parse(await req.text());
  } catch {
    record(`#${id} ${clock()} path=${path} bad-json`, true);
    return json({ error: "bad json body" }, 400, id);
  }

  const inputHash = shortHash({
    model: body?.model,
    system: body?.system,
    tools: body?.tools,
    messages: body?.messages,
  });
  const betaIn = headers.get("anthropic-beta") ?? "-";
  const bpIn = scanBreakpoints(body);
  const removedRuntime = removeOldRuntimeBlocks(body);

  const INJECT_CACHE = Deno.env.get("INJECT_CACHE") !== "0"; // 验水模式：INJECT_CACHE=0 纯透传不改内容
  let cacheNote = "off";
  if (CACHE_ENABLED && INJECT_CACHE) {
    const result = isMessagesPath(path)
      ? (BREAKPOINT_MODE === "all"
        ? injectAnthropicAll(body, TAIL_BREAKPOINTS)
        : injectAnthropicMessage(body))
      : injectOpenAI(body);
    cacheNote = result.skipped
      ? `skipped(${result.skipped}) applied[${result.applied.join(" ")}]`
      : `applied[${result.applied.join(" ")}]`;

    // As long as caching is enabled, always add beta on the Anthropic native path.
    // Do not add it only when the body changed, or requests already at 1h would miss it.
    if (isMessagesPath(path)) {
      headers.set("anthropic-beta", mergeBetaHeader(headers.get("anthropic-beta")));
    }
  }

  let timeNote = "off";
  if (TIME_ENABLED && isMessagesPath(path)) {
    const result = appendCurrentTime(body);
    timeNote = result.added ? "added-after-cache" : `skipped(${result.reason})`;
  }

  // v2: force non-stream (Anthropic messages path + incoming stream only)
  let streamNote = "passthrough";
  let convertSse = false;
  let streamUpstream = false;
  if (STREAM_UPSTREAM && isMessagesPath(path)) {
    body.stream = true;
    streamNote = "forced-true+std";
    streamUpstream = true;
  } else if (FORCE_NON_STREAM && isMessagesPath(path) && body?.stream === true) {
    body.stream = false;
    streamNote = "forced-false+sse";
    convertSse = true;
  }

  headers.set("content-type", "application/json");

  const messageCount = Array.isArray(body?.messages) ? body.messages.length : 0;
  const head = [
    `#${id}`,
    clock(),
    `path=${path}`,
    `model=${body?.model ?? "?"}`,
    `prompt=${inputHash}`,
    `sys=${diagnosticHash(body?.system)}`,
    `tools=${diagnosticHash(body?.tools)}`,
    `mh=${messageHashes(body)}`,
    `msgs=${messageCount}:${rolesOf(body)}`,
    `stream=${body?.stream === true}`,
    `force=${streamNote}`,
    `bpIn=${bpIn}`,
    `bpOut=${scanBreakpoints(body)}`,
    `cache=${cacheNote}`,
    `time=${timeNote}`,
    removedRuntime > 0 ? `oldTimeRemoved=${removedRuntime}` : "",
    `betaIn=${betaIn}`,
    `betaOut=${headers.get("anthropic-beta") ?? "-"}`,
  ].filter(Boolean).join(" ");

  if (LOG_BODY) {
    record(head + `\n  BODY ` + JSON.stringify(body));
  }

  return await forwardOnce(
    "POST",
    target,
    headers,
    JSON.stringify(body),
    { id, head, path, convertSse, streamUpstream },
  );
}

Deno.serve({ port: PORT }, handler);
