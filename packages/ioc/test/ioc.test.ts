import { describe, expect, it } from "vitest";
import { classifyIOC, parseBulkIOCs, refangIOC } from "../src/index";

describe("IOC utilities", () => {
  it("refangs common defanged indicators", () => {
    expect(refangIOC("hxxps://evil[.]example/path")).toBe("https://evil.example/path");
    expect(refangIOC("62[.]238[.]44[.]99")).toBe("62.238.44.99");
  });

  it("classifies IPs, domains, URLs, and hashes", () => {
    expect(classifyIOC("62.238.44.99").type).toBe("ip");
    expect(classifyIOC("evil.example").type).toBe("domain");
    expect(classifyIOC("https://evil.example/a").type).toBe("url");
    expect(classifyIOC("d41d8cd98f00b204e9800998ecf8427e").type).toBe("md5");
  });

  it("deduplicates bulk IOCs and enforces limits", () => {
    expect(parseBulkIOCs("evil[.]example evil.example")).toHaveLength(1);
    expect(() => parseBulkIOCs("a ".repeat(501), 500)).toThrow();
  });
});
