import { defineConfig } from "vite";

export default defineConfig({
  build: {
    emptyOutDir: true,
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
