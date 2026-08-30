// ============================================================
//  xyc-proxy v8.9-opus5-1h-4bp — passion 专用
//  ------------------------------------------------------------
//  在 v8.8 基础上: 全量标记改为点位式 4 断点(全 1h)
//    - tools末尾 / system末尾 / messages稳定前缀末尾 / 最后user前
//    全量44断点远超Anthropic官方上限4, 网关截断导致messages段
//    从未建缓存(read恒定=仅system+tools); 回归4点=整条前缀皆可命中
//  保留 v8.8: 键序规范化 + sanitize时间块 + 剔除 topic_reference +
//   末尾注入时间(在最后断点之后, 不占缓存前缀)
//
//  环境变量:
//    UPSTREAM_URL       默认 https://passion8.cc
//    UPGRADE_CACHE      1|0  默认 1
//    SANITIZE_TIME      1|0  默认 1(剔除动态时间块)
//    INJECT_TIME        1|0  默认 1(末尾注入当前时间)
//    PROXY_TOKEN        /logs* 保护
//    LOG_BODY           1|0  默认 1
//    MAX_LOGS           默认 250
//    PASSTHROUGH_OTHER  1|0  默认 1
//    RETRY              0|1  默认 0
// ============================================================

const VERSION = "v8.9-opus5-1h-4bp";
const UPSTREAM = (Deno.env.get("UPSTREAM_URL") || "https://passion8.cc").replace(/\/+$/, "");
const PROXY_TOKEN = Deno.env.get("PROXY_TOKEN") || "";
const LOG_BODY = Deno.env.get("LOG_BODY") !== "0";
const MAX_LOGS = Math.max(10, parseInt(Deno.env.get("MAX_LOGS") ?? "250", 10) || 250);
const PASSTHROUGH_OTHER = Deno.env.get("PASSTHROUGH_OTHER") !== "0";
const RETRY = Deno.env.get("RETRY") === "1";
const UPGRADE_CACHE = Deno.env.get("UPGRADE_CACHE") !== "0";
const SANITIZE_TIME = Deno.env.get("SANITIZE_TIME") !== "0";
const INJECT_TIME = Deno.env.get("INJECT_TIME") !== "0";
const BODY_CAP = 50000;
const TTL = "1h";
const BETA_1H = "extended-cache-ttl-2025-04-11";
const OPUS5_RE = /opus-?5/i;

// ---------- 小工具 ----------
function fnv(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}
const dec = new TextDecoder();
function nowStr(): string {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().replace("T", " ").slice(0, 19);
}
function rid(): string { return Math.random().toString(16).slice(2, 10); }
function brief(s: string, n: number): string { return s.length > n ? s.slice(0, n) + "...[cut]" : s; }
function json(o: unknown, status = 200): Response {
  return new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
}
function nowMinute(): string {
  const d = new Date(Date.now() + 8 * 3600 * 1000);
  const p = (x: number) => String(x).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
}

// ---------- 日志存储(内存, 重启即失) ----------
interface LogEntry {
  id: string;
  t: string;
  lines: string[];
  body?: string;
  result?: string;
}
const logs: LogEntry[] = [];
const lastBySys = new Map<string, { msgStable: string }>();
let seq = 0;

function addEntry(): LogEntry {
  if (logs.length >= MAX_LOGS) logs.shift();
  const e: LogEntry = { id: `${++seq}-${rid()}`, t: nowStr(), lines: [] };
  logs.push(e);
  return e;
}
function pushLine(e: LogEntry, s: string) {
  e.lines.push(s);
  console.log(`[${VERSION}] ${s}`);
}

// ---------- 动态时间块剔除(仅影响出站体与稳定性哈希) ----------
function sanitizeTimeText(s: string): string {
  let out = s
    .replace(/<runtime_context[\s\S]*?<\/runtime_context>/g, "")
    .replace(/<!--\s*pxy8-proxy-runtime-time-v1\s*-->/g, "")
    .replace(/<!--[^>]*(?:当前时间|当前北京时间|Current time)[^>]*-->/g, "");
  const lines = out.split("\n");
  const keep = lines.filter((ln) => !/(当前时间|当前北京时间|Current time|北京时间)\s*[：:]/.test(ln));
  return keep.join("\n");
}
function sanitizeSystemText(s: string): string {
  return s
    .replace(/<topic_reference_context>[\s\S]*?<\/topic_reference_context>/g, "")
    .replace(/<!--\s*SYSTEM CONTEXT[\s\S]*?END SYSTEM CONTEXT\s*-->/g, "");
}

// ---------- 请求体解析(只读) ----------
interface ScanResult {
  model: string;
  stream: string;
  roles: string;
  rawLen: number;
  msgHashes: string[];
  bpCount: number;
  bpPos: string[];
  sysHash: string;
  sysLen: number;
  toolsHash: string;
  toolsLen: number;
  msgStable: string;
  parsed: any;
  st: { hasPrev: boolean; stable: boolean; common: number; firstDiff: number };
  opus5: boolean;
}
function scanBody(raw: string): ScanResult {
  let parsed: any = null;
  try { parsed = JSON.parse(raw); } catch { /* 透传不受影响 */ }
  const model = String(parsed?.model ?? "-");
  const stream = typeof parsed?.stream === "boolean" ? String(parsed.stream) : (parsed?.stream === "true" ? "true" : "?");
  const msgs: any[] = parsed?.messages ?? [];
  const roles = msgs.map((m: any) => m?.role?.[0] ?? "?").join("");
  const rawLen = raw.length;

  const msgHashes: string[] = [];
  const bpPos: string[] = [];
  let bpCount = 0;
  msgs.forEach((m: any, i: number) => {
    const content = m?.content;
    let stable: string;
    if (typeof content === "string") stable = SANITIZE_TIME ? sanitizeTimeText(content) : content;
    else if (Array.isArray(content)) {
      const textOnly = content
        .filter((b: any) => typeof b === "object" && b?.type === "text")
        .map((b: any) => { const cp = { ...b }; delete cp.cache_control; return JSON.stringify(cp); });
      stable = SANITIZE_TIME ? sanitizeTimeText(textOnly.join("\n")) : textOnly.join("\n");
      for (const b of content) {
        if (b && typeof b === "object" && b.cache_control) {
          bpCount++;
          bpPos.push(`msg${i}.${b.type ?? "?"}:${b.cache_control.ttl ?? b.cache_control.type ?? "?"}`);
        }
      }
    } else stable = JSON.stringify(content);
    msgHashes.push(`${i}${m?.role?.[0] ?? "?"}:${fnv(stable)}/${stable.length}`);
  });

  const sys: any = parsed?.system;
  const sysStr = typeof sys === "string"
    ? (SANITIZE_TIME ? sanitizeSystemText(sanitizeTimeText(sys)) : sys)
    : JSON.stringify((sys ?? []).map((b: any) => {
        if (b && typeof b === "object" && typeof b.text === "string") {
          const cp = { ...b };
          delete cp.cache_control;
          cp.text = SANITIZE_TIME ? sanitizeSystemText(sanitizeTimeText(b.text)) : b.text;
          return cp;
        }
        return b;
      }));
  if (Array.isArray(sys)) {
    sys.forEach((s: any, i: number) => {
      if (s && s.cache_control) { bpCount++; bpPos.push(`sys${i}:${s.cache_control.ttl ?? s.cache_control.type ?? "?"}`); }
    });
  }
  const tools: any[] = parsed?.tools ?? [];
  const toolsStr = JSON.stringify(tools);
  tools.forEach((t: any, i: number) => {
    if (t && t.cache_control) { bpCount++; bpPos.push(`tool${i}:${t.cache_control.ttl ?? t.cache_control.type ?? "?"}`); }
  });

  const msgStable = msgHashes.join(",");
  const prev = lastBySys.get(fnv(sysStr));
  lastBySys.set(fnv(sysStr), { msgStable });
  let st = { hasPrev: false, stable: false, common: 0, firstDiff: -2 };
  if (prev) {
    const a = prev.msgStable.split(",").map((s: string) => s.slice(s.indexOf(":") + 1));
    const b = msgStable.split(",").map((s: string) => s.slice(s.indexOf(":") + 1));
    let common = 0;
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] === b[i]) common++; else break;
    }
    const firstDiff = common >= Math.min(a.length, b.length) ? -1 : common;
    st = { hasPrev: true, stable: firstDiff === -1 && b.length >= a.length, common, firstDiff };
  }

  return {
    model, stream, roles, rawLen, msgHashes, bpCount, bpPos,
    sysHash: fnv(sysStr), sysLen: sysStr.length,
    toolsHash: fnv(toolsStr), toolsLen: toolsStr.length,
    msgStable, parsed, st,
    opus5: OPUS5_RE.test(model),
  };
}

// ---------- opus5 点位式 4 断点 1h 改写 ----------
function rewrite1h(raw: string): { body: string; n: number } | null {
  let parsed: any;
  try { parsed = JSON.parse(raw); } catch { return null; }
  if (!parsed || typeof parsed !== "object") return null;
  if (!OPUS5_RE.test(String(parsed.model ?? ""))) return null;

  const bp = { type: "ephemeral", ttl: TTL };
  const cleanBlock = (block: any): any => {
    if (!block || typeof block !== "object" || Array.isArray(block)) return block;
    if (SANITIZE_TIME && typeof block.text === "string") block.text = sanitizeSystemText(sanitizeTimeText(block.text));
    return block;
  };
  const stripCC = (block: any): any => {
    if (!block || typeof block !== "object" || Array.isArray(block)) return block;
    delete block.cache_control;
    return block;
  };
  const canonify = (block: any): any => {
    if (!block || typeof block !== "object" || Array.isArray(block)) return block;
    const cc = block.cache_control;
    const out: any = {};
    if (block.type !== undefined) out.type = block.type;
    if (block.text !== undefined) out.text = block.text;
    for (const k of Object.keys(block)) {
      if (k === "type" || k === "text" || k === "cache_control") continue;
      out[k] = block[k];
    }
    if (cc) out.cache_control = cc;
    return out;
  };

  // system: 字符串->块; 数组->清理文本/键序/旧断点
  if (typeof parsed.system === "string") {
    if ((parsed.system as string).length) {
      parsed.system = [{ type: "text", text: sanitizeSystemText(sanitizeTimeText(parsed.system)) }];
    }
  } else if (Array.isArray(parsed.system)) {
    parsed.system = parsed.system.map(cleanBlock).map(stripCC).map(canonify);
  }

  // messages: 全部清理文本/键序/旧断点
  const msgs: any[] = parsed.messages ?? [];
  msgs.forEach((m: any) => {
    if (!m || typeof m !== "object") return;
    const c = m.content;
    if (typeof c === "string") {
      m.content = [{ type: "text", text: sanitizeSystemText(sanitizeTimeText(c)) }];
    } else if (Array.isArray(c)) {
      m.content = c
        .filter((b: any) => b && typeof b === "object")
        .map(cleanBlock)
        .map(stripCC)
        .map(canonify);
    }
  });

  // tools: 清理键序/旧断点
  if (Array.isArray(parsed.tools)) {
    parsed.tools = parsed.tools.map(stripCC).map(canonify);
  }

  // ===== 点位式 4 个 1h 断点 =====
  let n = 0;
  const put = (obj: any): void => {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) return;
    if (!obj.cache_control || obj.cache_control.ttl !== TTL) {
      obj.cache_control = { ...bp };
      n++;
    }
  };

  // 1) tools 最后一项
  const toolsArr: any[] = parsed.tools ?? [];
  if (toolsArr.length) put(toolsArr[toolsArr.length - 1]);

  // 2) system 最后一块(字符串时包成块)
  if (Array.isArray(parsed.system) && parsed.system.length) {
    put(parsed.system[parsed.system.length - 1]);
  } else if (typeof parsed.system === "string" && (parsed.system as string).length) {
    parsed.system = [{ type: "text", text: parsed.system, cache_control: { ...bp } }];
    n++;
  }

  // 3) messages 稳定前缀末尾 = 倒数第二条消息的最后一个块
  if (msgs.length >= 2) {
    const prevMsg = msgs[msgs.length - 2];
    const pc = prevMsg?.content;
    if (Array.isArray(pc) && pc.length) {
      put(pc[pc.length - 1]);
    } else if (typeof pc === "string" && pc.length) {
      prevMsg.content = [{ type: "text", text: pc, cache_control: { ...bp } }];
      n++;
    }
  }

  // 4) 最后一条 user 正文块打点(保证最新问题也被缓存前缀包含)
  if (msgs.length) {
    const lastMsg = msgs[msgs.length - 1];
    const lc = lastMsg?.content;
    if (Array.isArray(lc) && lc.length) {
      const textBlocks = lc.filter((b: any) => b && typeof b === "object" && b.type === "text");
      if (textBlocks.length) put(textBlocks[textBlocks.length - 1]);
    } else if (typeof lc === "string" && lc.length) {
      lastMsg.content = [{ type: "text", text: lc, cache_control: { ...bp } }];
      n++;
    }
  }

  // 末尾注入当前时间(在最后断点之后, 不带 cache_control)
  if (INJECT_TIME) {
    const last = msgs.length ? msgs[msgs.length - 1] : null;
    if (last && typeof last === "object") {
      const tb = `<!-- pxy8-proxy-runtime-time-v1 -->
<runtime_context source="request_proxy" updated_at="${nowMinute()}">
Current time: ${nowMinute()}
Time zone: Asia/Shanghai
This is runtime info added by the proxy, not the user's original text. Only use it when the question involves now, today, dates, deadlines or relative time.
</runtime_context>`;
      if (Array.isArray(last.content)) last.content.push({ type: "text", text: tb });
      else if (typeof last.content === "string") last.content = [{ type: "text", text: last.content }, { type: "text", text: tb }];
    }
  }

  return { body: JSON.stringify(parsed), n };
}

// ---------- 上游转发 ----------
function extractUsage(t: string): string | null {
  const fields: [string, RegExp][] = [
    ["in", /"input_tokens"\s*:\s*(\d+)/],
    ["out", /"output_tokens"\s*:\s*(\d+)/],
    ["read", /"cache_read_input_tokens"\s*:\s*(\d+)/],
    ["create", /"cache_creation_input_tokens"\s*:\s*(\d+)/],
    ["w1h", /"ephemeral_1h_input_tokens"\s*:\s*(\d+)/],
    ["w5m", /"ephemeral_5m_input_tokens"\s*:\s*(\d+)/],
    ["stop", /"stop_reason"\s*:\s*"([^"]+)"/],
  ];
  const parts: string[] = [];
  for (const [k, re] of fields) {
    const m = t.match(re);
    if (m) parts.push(`${k}=${m[1]}`);
  }
  return parts.length ? parts.join(" ") : null;
}
function finishAttempt(e: LogEntry, status: number, ms: number, len: number, bodyText: string) {
  const usage = extractUsage(bodyText);
  const line = `  attempt=1 status=${status} ms=${ms} len=${len}${usage ? " usage=" + usage : ""}` +
    (status >= 400 ? ` ERR-BODY <${brief(bodyText, 1500)}>` : "");
  e.result = line;
  pushLine(e, line);
}
function collect(e: LogEntry, stream: ReadableStream<Uint8Array>, status: number, ms: number) {
  const reader = stream.getReader();
  let len = 0;
  let text = "";
  (async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          len += value.byteLength;
          if (text.length < 1000000) text += dec.decode(value, { stream: true });
        }
      }
      finishAttempt(e, status, ms, len, text);
    } catch (err) {
      finishAttempt(e, status, ms, len, `[stream-error: ${err}]`);
    }
  })();
}

async function forwardMessage(e: LogEntry, raw: string, req: Request, rewN: number): Promise<Response> {
  const url = `${UPSTREAM}/v1/messages`;
  const headers = new Headers(req.headers);
  headers.delete("host");
  headers.delete("connection");
  headers.delete("transfer-encoding");
  headers.delete("x-proxy-token"); // 不透传代理自用 token 给上游
  if (rewN > 0) {
    const beta = headers.get("anthropic-beta") || "";
    if (!beta.includes(BETA_1H)) {
      headers.set("anthropic-beta", beta ? `${beta} ${BETA_1H}` : BETA_1H);
    }
  }
  const t0 = Date.now();

  const attempt = async (): Promise<{ resp: Response; ms: number }> => {
    const resp = await fetch(url, { method: "POST", headers, body: raw });
    return { resp, ms: Date.now() - t0 };
  };
  const respond = ({ resp, ms }: { resp: Response; ms: number }): Response => {
    if (resp.body) {
      const [a, b] = resp.body.tee();
      collect(e, b, resp.status, ms);
      return new Response(a, { status: resp.status, statusText: resp.statusText, headers: resp.headers });
    }
    finishAttempt(e, resp.status, ms, 0, "");
    return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: resp.headers });
  };

  try {
    const r = await attempt();
    return respond(r);
  } catch (err) {
    const msg = `  attempt=1 status=000 ms=${Date.now() - t0} ERR <${brief(String(err), 1500)}>`;
    e.result = msg;
    pushLine(e, msg);
    if (RETRY) {
      try {
        return respond(await attempt());
      } catch (err2) {
        const m2 = `  attempt=2 status=000 ms=${Date.now() - t0} ERR <${brief(String(err2), 1500)}>`;
        e.result = m2;
        pushLine(e, m2);
      }
    }
    return json({ error: { type: "upstream_unreachable", message: brief(String(err), 300) } }, 502);
  }
}

function summaryLine(e: LogEntry, req: Request, sIn: ScanResult, sOut: ScanResult, rewN: number) {
  const head =
    `#${e.id} ${e.t} path=/v1/messages model=${sOut.model} ` +
    `prompt=${fnv(JSON.stringify(sOut.parsed?.messages ?? []))}/${sOut.rawLen} ` +
    `sys=${sOut.sysHash}/${sOut.sysLen} tools=${sOut.toolsHash}/${sOut.toolsLen} ` +
    `msgs=${sOut.roles} stream=${sOut.stream} ` +
    (rewN > 0 ? `rewrite=1h:{${rewN}}` : `rewrite=none`) +
    ` sanitize=${SANITIZE_TIME ? 1 : 0} injectTime=${INJECT_TIME ? 1 : 0} ` +
    (sIn.bpCount ? `bpIn=${sIn.bpCount}[${sIn.bpPos.join(",")}]` : "bpIn=0") +
    (sOut.bpCount ? ` bpOut=${sOut.bpCount}[${sOut.bpPos.join(",")}]` : "") +
    (sOut.st.hasPrev
      ? ` prefixStable=${sOut.st.stable} common=${sOut.st.common} firstDiff=${sOut.st.firstDiff}`
      : " firstRequest") +
    ` betaIn=${req.headers.get("anthropic-beta") || "-"}` +
    (rewN > 0 ? ` betaOut=${BETA_1H}` : "");
  pushLine(e, head);
}

// ---------- 路由 ----------
function authed(req: Request): boolean {
  if (!PROXY_TOKEN) return true;
  if (new URL(req.url).searchParams.get("proxy_token") === PROXY_TOKEN) return true;
  return req.headers.get("x-proxy-token") === PROXY_TOKEN;
}

async function passthroughGeneric(req: Request, p: string): Promise<Response> {
  const e = addEntry();
  pushLine(e, `#${e.id} ${e.t} path=${p} passthrough`);
  const headers = new Headers(req.headers);
  headers.delete("host");
  headers.delete("connection");
  headers.delete("transfer-encoding");
  headers.delete("x-proxy-token");
  const up = `${UPSTREAM}${p}${new URL(req.url).search}`;
  const t0 = Date.now();
  const buf = req.method === "GET" || req.method === "HEAD" ? undefined : await req.arrayBuffer();
  try {
    const resp = await fetch(up, { method: req.method, headers, body: buf as BodyInit | undefined });
    pushLine(e, `  status=${resp.status} ms=${Date.now() - t0}`);
    return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: resp.headers });
  } catch (err) {
    pushLine(e, `  status=000 ms=${Date.now() - t0} ERR <${brief(String(err), 500)}>`);
    return new Response(String(err), { status: 502 });
  }
}

function renderEntryBody(e: LogEntry): string {
  return e.body ? `  BODY ${e.body}\n` : "";
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const p = url.pathname;

  if (p === "/" || p === "/health") {
    return json({
      ok: true, provider: "passion8", version: VERSION,
      upstream: UPSTREAM, mode: "passthrough+opus5-1h(4bp)",
      rewrite: UPGRADE_CACHE ? "opus5->4x1h-points+sanitize+canon+sys-stable+inject-time" : "none",
      sanitizeTime: SANITIZE_TIME, injectTime: INJECT_TIME, forceNonStream: false,
      logsInThisInstance: logs.length, maxLogs: MAX_LOGS, distinctSystems: lastBySys.size,
    });
  }
  if (p === "/logs" || p === "/logs.json" || p === "/logs/clear") {
    if (!authed(req)) return new Response("forbidden", { status: 403 });
    if (p === "/logs/clear") { logs.length = 0; return json({ ok: true, cleared: true }); }
    if (p === "/logs.json") {
      return json({
        count: logs.length, distinctSystems: lastBySys.size, version: VERSION,
        logs: logs.map((e) => ({
          id: e.id, t: e.t, lines: e.lines.join("\n"), result: e.result ?? null,
          body: LOG_BODY ? (e.body ?? null) : null,
        })),
      });
    }
    return new Response(logs.map((e) => e.lines.join("\n") + (LOG_BODY ? "\n" + renderEntryBody(e) : "")).join("\n"), {
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }
  if (p === "/v1/messages" && req.method === "POST") {
    const raw = await req.text();
    const e = addEntry();
    const sIn = scanBody(raw);
    let outRaw = raw;
    let rewN = 0;
    let sOut = sIn;
    if (UPGRADE_CACHE && sIn.opus5) {
      const r = rewrite1h(raw);
      if (r) {
        outRaw = r.body;
        rewN = r.n;
        sOut = scanBody(outRaw); // 前缀稳定性按实际出站体计算
      }
    }
    summaryLine(e, req, sIn, sOut, rewN);
    if (LOG_BODY) e.body = brief(outRaw, BODY_CAP);
    return await forwardMessage(e, outRaw, req, rewN);
  }
  if (PASSTHROUGH_OTHER) return await passthroughGeneric(req, p);
  return json({ error: "not found" }, 404);
}

// ---------- 启动 ----------
const port = parseInt(Deno.env.get("PORT") || "8080", 10);
console.log(`${VERSION} upstream=${UPSTREAM} port=${port} UPGRADE_CACHE=${UPGRADE_CACHE} SANITIZE_TIME=${SANITIZE_TIME} INJECT_TIME=${INJECT_TIME} LOG_BODY=${LOG_BODY} MAX_LOGS=${MAX_LOGS} PROXY_TOKEN=${PROXY_TOKEN ? "set" : "none"}`);
Deno.serve({ port }, handle);
