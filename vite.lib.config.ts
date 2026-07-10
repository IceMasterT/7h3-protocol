import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    lib: {
      entry: 'src/index.ts',
      formats: ['es'],
      fileName: () => 'index.js',
    },
    outDir: 'dist/protocol',
    emptyOutDir: false,
    rollupOptions: {
      // Vite's lib build targets the browser by default and rewrites `node:*`
      // imports to __vite-browser-external, an empty shim. That turned
      // `createPrivateKey` into a missing export and broke the build outright;
      // node:http / node:readline / node:stream were being silently stubbed.
      // @7h3/protocol is a Node ESM library with zero runtime deps, so the
      // builtins must stay as real imports in the output.
      external: [/^node:/],
    },
  },
})
