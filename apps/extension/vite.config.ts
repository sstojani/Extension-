import { defineConfig } from "vite";

export default defineConfig({
  build: {
    // Static MV3 files are copied into dist alongside the bundles.
    // Keep them in place for watch builds so Chrome always sees a manifest.
    emptyOutDir: false,
    outDir: "dist",
    sourcemap: true,
    rollupOptions: {
      input: {
        "service-worker": "src/service-worker.ts",
        "content-script": "src/content-script.ts"
      },
      output: {
        entryFileNames: "[name].js"
      }
    }
  }
});
