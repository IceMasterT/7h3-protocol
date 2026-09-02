import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

const protocolSource = fileURLToPath(new URL('./src/index.ts', import.meta.url))

export default defineConfig({
  resolve: {
    alias: [
      {
        // Resolve '@7h3/protocol' and every subpath to in-repo source.
        //
        // Without this, any test importing the package (sdk/webmcp, cloudflare/)
        // only resolves after `npm run build:protocol`, because package.json
        // points at gitignored dist/ — so a clean clone failed with a
        // misleading error rather than "you need to build first".
        //
        // Mapping subpaths to the same entry mirrors what ships: every subpath's
        // "import" condition already resolves to the one bundled
        // dist/protocol/index.js. Only the type declarations are per-module.
        find: /^@7h3\/protocol(\/.*)?$/,
        replacement: protocolSource,
      },
    ],
  },
  test: {
    exclude: [
      'sdk/pq/dist/**',
      'sdk/threshold/dist/**',
      '**/node_modules/**',
    ],
  },
})
