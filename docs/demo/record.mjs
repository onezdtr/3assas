// Films the demo page (gen.py on 127.0.0.1:8056) through a headless Chromium started with --remote-debugging-port=9335.
// node docs/demo/record.mjs <frames dir>     then: sh docs/demo/gif.sh <frames dir>
import { mkdirSync, writeFileSync } from "node:fs";

const [dir] = process.argv.slice(2);
mkdirSync(dir, { recursive: true });
const target = await (await fetch("http://127.0.0.1:9335/json/new?about:blank", { method: "PUT" })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((ok) => ws.addEventListener("open", ok));
let id = 0;
const waiting = new Map(), frames = [];
ws.addEventListener("message", (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && waiting.has(msg.id)) { waiting.get(msg.id)(msg.result); waiting.delete(msg.id); }
  if (msg.method === "Page.screencastFrame") {
    frames.push([msg.params.metadata.timestamp, msg.params.data]);
    send("Page.screencastFrameAck", { sessionId: msg.params.sessionId });
  }
});
const send = (method, params = {}) => new Promise((ok) => { waiting.set(++id, ok); ws.send(JSON.stringify({ id, method, params })); });
const pause = (ms) => new Promise((ok) => setTimeout(ok, ms));
const js = async (code) => (await send("Runtime.evaluate", { expression: code, awaitPromise: true, returnByValue: true })).result.value;

async function click(text) {
  const [x, y] = await js(`(() => { const r = [...document.querySelectorAll("#programs tr.row")]
    .find((r) => r.querySelector(".exe").textContent === ${JSON.stringify(text)}).getBoundingClientRect();
    return [r.x + 120, r.y + r.height / 2]; })()`);
  await send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
  await pause(350);
  for (const type of ["mousePressed", "mouseReleased"]) await send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 });
}
async function scroll(to, steps = 24) {
  const from = await js("scrollY");
  for (let i = 1; i <= steps; i++) {
    const k = i / steps, ease = k < 0.5 ? 2 * k * k : 1 - (-2 * k + 2) ** 2 / 2;
    await js(`scrollTo(0, ${from + (to - from) * ease})`);
    await pause(30);
  }
}

await send("Emulation.setDeviceMetricsOverride", { width: 1200, height: 760, deviceScaleFactor: 1, mobile: false });
await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
await send("Page.navigate", { url: "http://127.0.0.1:8056/" });
await pause(2500);

await send("Page.startScreencast", { format: "png", everyNthFrame: 1 });
await pause(2200);
await click("upd");  // the suspicious one: where did it go?
await pause(3200);
await click("upd");
await pause(400);
await click("firefox");
await pause(2600);
await click("firefox");
await scroll(await js("document.querySelector('.feed').offsetTop - 20"));
await pause(3400);  // live feed
await scroll(0);
await pause(1200);
await send("Page.stopScreencast");

frames.sort((a, b) => a[0] - b[0]);
const end = frames.at(-1)[0] + 1;
let list = "ffconcat version 1.0\n";
frames.forEach(([t, data], k) => {
  const f = `${String(k).padStart(4, "0")}.png`;
  writeFileSync(`${dir}/${f}`, Buffer.from(data, "base64"));
  list += `file ${f}\nduration ${((frames[k + 1]?.[0] ?? end) - t).toFixed(3)}\n`;
});
writeFileSync(`${dir}/list.txt`, list + `file ${String(frames.length - 1).padStart(4, "0")}.png\n`);
console.log(`${frames.length} frames over ${(end - 1 - frames[0][0]).toFixed(1)} s`);
process.exit(0);
