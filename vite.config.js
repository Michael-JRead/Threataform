import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      // Don't intercept wllama WASM or cross-origin resources —
      // only cache the app shell (JS/CSS/HTML) for offline-first load.
      workbox: {
        // WASM files are large and streamed; let the browser handle them
        globIgnores: ["**/*.wasm", "**/*.gguf"],
        globPatterns: ["**/*.{js,css,html,ico,png,svg,webmanifest}"],
        // Network-first for API-like fetches; cache-first for static assets
        runtimeCaching: [
          {
            urlPattern: /^https:\/\/huggingface\.co\/.*/i,
            handler: "CacheFirst",
            options: {
              cacheName: "hf-models-cache",
              expiration: { maxEntries: 10, maxAgeSeconds: 60 * 60 * 24 * 30 },
            },
          },
        ],
        // Service worker must add COEP/COOP headers to cached responses
        // so SharedArrayBuffer works after the SW serves them
        additionalManifestEntries: [],
        navigateFallback: "/index.html",
        navigateFallbackDenylist: [/^\/api/],
      },
      manifest: {
        name: "Threataform",
        short_name: "Threataform",
        description: "Enterprise Terraform Threat Intelligence — offline, air-gap ready",
        theme_color: "#f97316",
        background_color: "#0d0d0d",
        display: "standalone",
        icons: [
          { src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any maskable" },
          { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any maskable" },
        ],
      },
      devOptions: {
        // Enable SW in dev so we can verify the manifest and registration
        enabled: false, // Keep disabled in dev (COEP + SW together is complex)
      },
    }),
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
    // Exclude WASM-heavy packages from Vite's pre-bundler so they load as-is
    exclude: ["@wllama/wllama"],
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
