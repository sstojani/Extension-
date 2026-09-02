import { defineConfig } from "vite";

export default defineConfig({
  build: {
    emptyOutDir: true,
    outDir: "dist",
    sourcemap: true,
    lib: {
      entry: "src/service-worker.ts",
      formats: ["es"],
      fileName: () => "service-worker.js"
    },
    rollupOptions: {
      output: {
        entryFileNames: "service-worker.js"
      }
    }
  }
});
