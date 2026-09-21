import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const crcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const extensionRoot = join(projectRoot, "apps", "extension");
const distRoot = join(extensionRoot, "dist");
const manifest = JSON.parse(await readFile(join(distRoot, "manifest.json"), "utf8"));
const version = String(manifest.version);
const packageFolder = `soc-watch-bridge-v${version}`;
const outputRoot = join(projectRoot, "apps", "web", "public", "downloads");
const outputPath = join(outputRoot, `${packageFolder}.zip`);

const files = await collectFiles(distRoot);
const entries = [];

for (const absolutePath of files) {
  const archivePath = `${packageFolder}/${relative(distRoot, absolutePath).split(sep).join("/")}`;
  entries.push({ name: archivePath, data: await readFile(absolutePath) });
}

entries.push({
  name: `${packageFolder}/INSTALL.txt`,
  data: Buffer.from([
    "SOC Watch Bridge installation",
    "",
    "1. Extract this ZIP to a permanent folder.",
    "2. Open chrome://extensions in Google Chrome.",
    "3. Enable Developer mode.",
    "4. Select Load unpacked.",
    `5. Select the extracted ${packageFolder} folder containing manifest.json.`,
    "6. Copy the extension ID shown by Chrome into the SOC Watch installation screen.",
    "7. Select Reload and Verify in SOC Watch.",
    "",
    `Package version: ${version}`,
    "The extension is read-only and uses the analyst's existing authenticated Kibana session.",
    ""
  ].join("\r\n"), "utf8")
});

await mkdir(outputRoot, { recursive: true });
await writeFile(outputPath, createZip(entries));
console.log(`Packaged ${entries.length} extension files at ${outputPath}`);

async function collectFiles(root) {
  const results = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const absolutePath = join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...await collectFiles(absolutePath));
      continue;
    }
    if (entry.isFile() && !entry.name.endsWith(".map")) results.push(absolutePath);
  }
  return results.sort((left, right) => left.localeCompare(right));
}

function createZip(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const { dosDate, dosTime } = zipDate(new Date());

  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const data = Buffer.from(entry.data);
    const checksum = crc32(data);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0x0800, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(data.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(name.length, 26);
    localHeader.writeUInt16LE(0, 28);
    localParts.push(localHeader, name, data);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(data.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    centralParts.push(centralHeader, name);

    offset += localHeader.length + name.length + data.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirectory, end]);
}

function zipDate(date) {
  const year = Math.max(date.getFullYear(), 1980);
  return {
    dosDate: ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate(),
    dosTime: (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2)
  };
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
