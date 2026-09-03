/**
 * Landing hub.
 *
 * Three demos rather than one, because "it works" means different things to
 * different readers: some want to see a product, some want to see what the
 * guard actually prevents, and some want to check the cryptography themselves.
 */

import { isWebMcpSupported } from '@7h3/protocol-webmcp'
import './styles.css'

interface Demo {
  href: string
  title: string
  kind: string
  blurb: string
  shows: string[]
  cta: string
}

const DEMOS: Demo[] = [
  {
    href: '/ledger',
    title: 'Ledger',
    kind: 'The product',
    blurb:
      'A real business console — invoices, customers, payments — with ten WebMCP tools an agent can drive. ' +
      'Grant it "pay invoices, $50 ceiling, ten minutes", then watch it get refused the moment it steps outside that.',
    shows: [
      'Ten tools registered on document.modelContext (3 read, 7 write)',
      'Scoped, expiring grants with a spend cap signed into the token',
      'Every call receipted — allowed and refused',
      'A lookalike tool injected at runtime, and caught',
    ],
    cta: 'Open the console',
  },
  {
    href: '/compare',
    title: 'Same attack, twice',
    kind: 'The counterfactual',
    blurb:
      'A refusal only means something if you can see what happens without one. ' +
      'One compromised agent runs the same four actions against two identical copies of the books — ' +
      'one wired straight to its handlers, one behind the guard.',
    shows: [
      'Identical tools, identical inputs, one difference',
      '$2,750 moved and 4 customer records exfiltrated on one side',
      'Nothing moved, and every attempt recorded, on the other',
      'One click, no setup, works in any browser',
    ],
    cta: 'Run the attack',
  },
  {
    href: '/verify',
    title: 'Verify it yourself',
    kind: 'The proof',
    blurb:
      'Do not take the UI’s word for it. Read the actual signed grant, the hash-chained receipts and the ' +
      'tool manifest, edit any of them by hand, and watch verification fail at exactly the byte you changed.',
    shows: [
      'The real Ed25519 signatures, shown in full',
      'prevHash links between receipts, and what breaks them',
      'Tamper with anything and see the exact index that fails',
      'The manifest fetched live and checked against the published key',
    ],
    cta: 'Inspect the crypto',
  },
]

const root = document.getElementById('root')!
const esc = (s: unknown) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)

const supported = isWebMcpSupported()

root.innerHTML = `
<header>
  <div class="brand">7h3<span> × </span>WebMCP</div>
  <div class="tagline">signed, capability-scoped, receipted tools for browser agents</div>
  <div class="spacer"></div>
  <span class="pill ${supported ? 'ok' : 'off'}">${supported ? 'WebMCP detected' : 'no WebMCP agent here — every demo still works'}</span>
</header>

<div class="layout" style="grid-template-columns: minmax(0,1fr)">
  <div>
    <div class="card">
      <div class="card-body">
        <div style="font-size:19px;font-weight:600;letter-spacing:-.01em;margin-bottom:8px">
          WebMCP gives agents hands. This gives those hands a signature, a scope, and a receipt.
        </div>
        <div class="hint" style="padding:0">
          Chrome’s agent security guidance is entirely probabilistic — classifiers, spotlighting, critic LLMs —
          and silent on authorization. OpenAI’s own docs say a tool’s name “isn’t proof of what it does”, then tell
          sites to use their <em>existing</em> authorization, which for delegated agent action does not exist.
          This is that missing layer, and it is deterministic: <strong>a refusal is a failed signature or an
          uncovered scope, not a judgement call.</strong>
        </div>
      </div>
    </div>

    ${DEMOS.map(
      (d, i) => `
      <div class="card">
        <h2>${i + 1}. ${esc(d.kind)} <span class="count">${esc(d.title)}</span></h2>
        <div class="card-body">
          <div style="margin-bottom:10px">${esc(d.blurb)}</div>
          ${d.shows.map((s) => `<div class="receipt allowed" style="border:none;padding:5px 0"><div class="dot"></div><div class="tool" style="font-weight:400">${esc(s)}</div></div>`).join('')}
          <div class="rowflex" style="margin-top:14px">
            <a href="${esc(d.href)}"><button class="primary">${esc(d.cta)} →</button></a>
          </div>
        </div>
      </div>`,
    ).join('')}

    <div class="card">
      <h2>Driving it with a real agent</h2>
      <div class="card-body">
        <div class="hint" style="padding:0 0 10px">
          Every demo above runs in any browser. To drive the tools with an actual agent you need one of:
        </div>
        <div class="receipt allowed"><div class="dot"></div><div><div class="tool">ChatGPT desktop app</div><div class="why">GPT-5.6 Sol or Terra — Luna has WebMCP disabled. Open the page in the app’s built-in browser, then check <strong>Site tools</strong> in the address bar.</div></div></div>
        <div class="receipt allowed"><div class="dot"></div><div><div class="tool">Chrome 149+</div><div class="why">Enable <code>chrome://flags/#enable-webmcp-testing</code> and relaunch. There is no extension to install — it is built in.</div></div></div>
        <div class="hint">
          Full walkthrough, including what each step should return:
          <a href="https://github.com/IceMasterT/7h3-protocol/blob/main/docs/TESTING.md">docs/TESTING.md</a>
        </div>
      </div>
    </div>
  </div>
</div>`
