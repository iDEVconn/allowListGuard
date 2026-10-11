import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    fastify: "src/fastify/index.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "es2022",
  external: ["@nestjs/common", "@nestjs/core", "fastify", "reflect-metadata", "rxjs"],
});
