import { isAllowedOrigin } from "@soc-watch/protocol";
import { describe, expect, it } from "vitest";
import { DEFAULT_ALLOWED_ORIGINS } from "../src/config";

describe("SOC Watch deployment origins", () => {
  it("allows only the approved Tailscale deployment ports", () => {
    expect(
      isAllowedOrigin("https://laptop-1.tail029be8.ts.net:8443/", DEFAULT_ALLOWED_ORIGINS)
    ).toBe(true);
    expect(
      isAllowedOrigin("https://laptop-1.tail029be8.ts.net/", DEFAULT_ALLOWED_ORIGINS)
    ).toBe(true);
    expect(
      isAllowedOrigin("https://laptop-1.tail029be8.ts.net:443/", DEFAULT_ALLOWED_ORIGINS)
    ).toBe(true);
    expect(
      isAllowedOrigin("https://laptop-1.tail029be8.ts.net:10000/", DEFAULT_ALLOWED_ORIGINS)
    ).toBe(false);
  });
});
