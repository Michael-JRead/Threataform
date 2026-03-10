import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [
    react(),
  ],
  server: {
    port: 5173,
    host: "127.0.0.1",
    headers: {
      // Required for SharedArrayBuffer (multi-thread wllama) and WASM SIMD
      "Cross-Origin-Opener-Policy":   "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
  },
  worker: {
    format: "es",
  },
  optimizeDeps: {
    // Exclude WASM-heavy packages from Vite's pre-bundler so they load as-is.
    // @huggingface/transformers is optional (cross-encoder reranker); the app
    // falls back to RRF ranking if it is absent. Excluding it here prevents
    // Vite from erroring when the package is not installed.
    exclude: ["@wllama/wllama", "@huggingface/transformers"],
  },
  // Serve .wasm and .tnlm files as static assets (not base64-inlined)
  assetsInclude: ["**/*.wasm", "**/*.tnlm"],
  build: {
    target: "esnext",
    rollupOptions: {
      output: {
        // Keep WASM files as separate chunks so browsers can stream-compile them
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
});
