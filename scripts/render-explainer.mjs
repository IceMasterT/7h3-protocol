#!/usr/bin/env node
/**
 * Render docs/assets/explainer.html -> explainer.mp4 (+ explainer.gif).
 *
 * The page is a pure function of time (`setT(t)`), so frames are captured
 * deterministically over the Chrome DevTools Protocol rather than screen-recorded.
 * Needs Chrome/Chromium, ffmpeg, and Node >= 22 (global WebSocket).
 *
 *   node scripts/render-explainer.mjs [--fps=24] [--no-gif]
 */
import { spawn, execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const html = path.join(root, 'docs/assets/explainer.html')
const out = path.join(root, 'docs/assets')
const fps = Number((process.argv.find(a => a.startsWith('--fps=')) ?? '--fps=24').slice(6))
const wantGif = !process.argv.includes('--no-gif')
const chromeBin = process.env.CHROME_PATH ?? 'google-chrome'

const work = mkdtempSync(path.join(tmpdir(), 'explainer-'))
const framesDir = path.join(work, 'frames'); mkdirSync(framesDir)
const port = 9300 + Math.floor(Math.random() * 500)
const chrome = spawn(chromeBin, [
  '--headless=new', '--disable-gpu', '--hide-scrollbars', `--remote-debugging-port=${port}`,
  `--user-data-dir=${path.join(work, 'profile')}`, '--window-size=1080,1080', 'about:blank',
], { stdio: 'ignore' })

const sleep = ms => new Promise(r => setTimeout(r, ms))
async function wsUrl() {
  for (let i = 0; i < 50; i++) {
    try {
      const tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json()
      const page = tabs.find(t => t.type === 'page'); if (page) return page.webSocketDebuggerUrl
    } catch {}
    await sleep(200)
  }
  throw new Error('Chrome DevTools did not come up')
}

try {
  const ws = new WebSocket(await wsUrl())
  await new Promise(r => ws.addEventListener('open', r))
  let id = 0; const pending = new Map()
  ws.addEventListener('message', e => { const m = JSON.parse(e.data); pending.get(m.id)?.(m); pending.delete(m.id) })
  const send = (method, params = {}) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })) })

  await send('Emulation.setDeviceMetricsOverride', { width: 1080, height: 1080, deviceScaleFactor: 1, mobile: false })
  await send('Page.navigate', { url: 'file://' + html + '?manual=1' })
  await sleep(2500) // fonts
  const duration = (await send('Runtime.evaluate', { expression: 'DURATION', returnByValue: true })).result.result.value
  const total = Math.round(duration * fps)
  for (let f = 0; f < total; f++) {
    await send('Runtime.evaluate', { expression: `setT(${f / fps})` })
    const shot = await send('Page.captureScreenshot', { format: 'png' })
    writeFileSync(path.join(framesDir, `f${String(f).padStart(5, '0')}.png`), Buffer.from(shot.result.data, 'base64'))
  }
  ws.close()

  const input = ['-y', '-framerate', String(fps), '-i', path.join(framesDir, 'f%05d.png')]
  execFileSync('ffmpeg', [...input, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '18', '-movflags', '+faststart', path.join(out, 'explainer.mp4')], { stdio: 'ignore' })
  console.log('wrote docs/assets/explainer.mp4')
  if (wantGif) {
    execFileSync('ffmpeg', ['-y', '-framerate', String(fps), '-i', path.join(framesDir, 'f%05d.png'),
      '-vf', 'fps=15,scale=720:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=bayer:bayer_scale=4',
      path.join(out, 'explainer.gif')], { stdio: 'ignore' })
    console.log('wrote docs/assets/explainer.gif')
  }
} finally { chrome.kill() }
