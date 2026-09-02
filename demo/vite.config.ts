import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

/**
 * The demo bundles the protocol and the WebMCP guard straight from repo source.
 *
 * Both are pure Web Crypto with zero dependencies, so they bundle for the
 * browser unchanged — no polyfills, no Node shims.
 */
export default defineConfig({
  resolve: {
    alias: [
      {
        find: /^@7h3\/protocol$/,
        replacement: fileURLToPath(new URL('./src/protocol-browser.ts', import.meta.url)),
      },
      {
        find: /^@7h3\/protocol-webmcp$/,
        replacement: fileURLToPath(new URL('../sdk/webmcp/src/index.ts', import.meta.url)),
      },
    ],
  },
  build: { outDir: 'dist', emptyOutDir: true, target: 'es2022' },
})
