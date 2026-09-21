export type KnownInfrastructure = {
  kind: "public_dns";
  provider: string;
};

const PUBLIC_DNS_PROVIDERS: Record<string, string> = {
  "1.0.0.1": "Cloudflare Public DNS",
  "1.1.1.1": "Cloudflare Public DNS",
  "8.8.4.4": "Google Public DNS",
  "8.8.8.8": "Google Public DNS",
  "9.9.9.9": "Quad9 Public DNS",
  "94.140.14.14": "AdGuard Public DNS",
  "94.140.15.15": "AdGuard Public DNS",
  "149.112.112.112": "Quad9 Public DNS",
  "208.67.220.220": "Cisco OpenDNS",
  "208.67.222.222": "Cisco OpenDNS",
  "2001:4860:4860::8844": "Google Public DNS",
  "2001:4860:4860::8888": "Google Public DNS",
  "2606:4700:4700::1001": "Cloudflare Public DNS",
  "2606:4700:4700::1111": "Cloudflare Public DNS",
  "2620:119:35::35": "Cisco OpenDNS",
  "2620:119:53::53": "Cisco OpenDNS",
  "2620:fe::9": "Quad9 Public DNS",
  "2620:fe::fe": "Quad9 Public DNS"
};

export const KNOWN_PUBLIC_DNS_IPS = Object.freeze(Object.keys(PUBLIC_DNS_PROVIDERS));

const RESOLVER_PORTS = new Set([53, 443, 853]);
const THREAT_CONTEXT = /(?:malware|ransom|trojan|botnet|command.?and.?control|\bc2\b|exfiltrat|phish|exploit|shellcode|webshell|credential.?theft)/i;
const SECURITY_DATASET = /(?:\.alerts?(?:\.|$)|detection|endpoint|malware|threat)/i;

export function getKnownInfrastructure(ip: string): KnownInfrastructure | undefined {
  const provider = PUBLIC_DNS_PROVIDERS[ip.trim().toLowerCase()];
  return provider ? { kind: "public_dns", provider } : undefined;
}

export function isRoutineKnownInfrastructureTraffic(input: {
  destinationIp: string;
  ports: number[];
  actions: Array<{ key: string }>;
  datasets: Array<{ key: string }>;
}): boolean {
  const known = getKnownInfrastructure(input.destinationIp);
  if (!known || known.kind !== "public_dns" || input.ports.length === 0) return false;
  if (!input.ports.every((port) => RESOLVER_PORTS.has(port))) return false;
  if (input.actions.some((item) => THREAT_CONTEXT.test(item.key))) return false;
  if (input.datasets.some((item) => SECURITY_DATASET.test(item.key))) return false;
  return true;
}
