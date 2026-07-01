import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
  },
  resolve: {
    alias: {
      '@7h3/protocol': '/tmp/aip-work/src/protocol.ts',
    },
  },
})
