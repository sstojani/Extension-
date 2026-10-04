import { existsSync, mkdirSync, readFileSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync, chmodSync, rmSync, lstatSync } from "node:fs";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";

const names = ["gti", "threatfox", "malwarebazaar"];
const validKey = value => typeof value === "string" && value.length <= 4096 && !/[\r\n\0]/.test(value);

export class Integrations {
  constructor(runtime) {
    this.runtime = runtime;
    this.environment = { gti: runtime.gtiKey?.trim() || "", threatfox: runtime.feeds?.threatfox?.trim() || "", malwarebazaar: runtime.feeds?.malwarebazaar?.trim() || "" };
    this.path = resolve(runtime.dataDir, "integrations.json");
    this.saved = {};
    if (existsSync(this.path)) {
      try {
        if (lstatSync(this.path).isSymbolicLink()) throw new Error();
        const value = JSON.parse(readFileSync(this.path, "utf8"));
        if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(name => !names.includes(name) || !validKey(value[name]))) throw new Error();
        this.saved = value;
        chmodSync(this.path, 0o600);
      } catch { throw new Error("Saved server integrations could not be read. Check the protected data directory; keys have not been reset."); }
    }
    this.apply();
  }
  apply() {
    this.runtime.gtiKey = this.environment.gti || this.saved.gti || "";
    this.runtime.feeds = { threatfox: this.environment.threatfox || this.saved.threatfox || "", malwarebazaar: this.environment.malwarebazaar || this.saved.malwarebazaar || "" };
  }
  status() {
    return Object.fromEntries(names.map(name => [name, { configured: Boolean(this.environment[name] || this.saved[name]),
      source: this.environment[name] ? "environment" : this.saved[name] ? "server" : "missing" }]));
  }
  save(body) {
    if (Object.keys(body).some(name => !names.includes(name) && name !== "remove")
      || body.remove !== undefined && (!Array.isArray(body.remove) || body.remove.some(name => !names.includes(name)))) throw new Error("Invalid integration settings.");
    const next = { ...this.saved };
    for (const name of names) {
      if (body[name] !== undefined && !validKey(body[name])) throw new Error("Invalid integration key.");
      if ((body[name]?.trim() || body.remove?.includes(name)) && this.environment[name]) throw new Error("This key is managed by the service environment. Update its protected environment file and restart the service.");
      if (body[name]?.trim() && body.remove?.includes(name)) throw new Error("Choose either replacing or removing a key.");
      if (body[name]?.trim()) next[name] = body[name].trim();
      if (body.remove?.includes(name)) delete next[name];
    }
    mkdirSync(this.runtime.dataDir, { recursive: true, mode: 0o700 });
    const temporary = `${this.path}.${randomUUID()}.tmp`;
    try {
      const fd = openSync(temporary, "wx", 0o600);
      try { writeFileSync(fd, JSON.stringify(next)); fsyncSync(fd); } finally { closeSync(fd); }
      renameSync(temporary, this.path);
    } catch {
      try { rmSync(temporary, { force: true }); } catch { /* Preserve the original save failure. */ }
      throw new Error("Server integration keys could not be saved. Check data-directory write permissions. Existing keys are unchanged.");
    }
    const gtiChanged = next.gti !== this.saved.gti;
    this.saved = next; this.apply();
    return { gtiChanged, integrations: this.status() };
  }
}
