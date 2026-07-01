import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    exclude: [
      'sdk/pq/dist/**',
      'sdk/threshold/dist/**',
      '**/node_modules/**',
    ],
  },
})
