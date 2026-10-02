import { classifyIOC } from "@soc-watch/ioc";
import { z } from "zod";
import { collectThreatIntelSnapshot, type ThreatIntelIOC, type ThreatIntelProviderStatus } from "./threat-intel";

export const HUNT_CAMPAIGN_KEY = "iocHuntCampaign";
export const HUNT_CAMPAIGN_LEASE_KEY = "iocHuntCampaignLease";
export const HUNT_CAMPAIGN_TTL_MS = 24 * 60 * 60 * 1000;
export const HUNT_CAMPAIGN_LEASE_MS = 2 * 60 * 1000;
export const HUNT_CAMPAIGN_MAX_IOCS = 100_000;
export const HUNT_CAMPAIGN_MAX_BYTES = 6 * 1024 * 1024;
export const HUNT_BATCH_LIMIT = 500;

const countSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const textSchema = z.string().max(16_384);
const querySchema = z.object({
  indexPattern: z.string().min(1).max(512),
  timestampField: z.string().min(1).max(256),
  from: z.string().min(1).max(128),
  to: z.string().min(1).max(128)
}).strict();
const iocSchema = z.object({
  original: textSchema,
  normalized: textSchema.min(1),
  type: z.enum(["ip", "domain", "url", "md5", "sha1", "sha256"]),
  sources: z.array(z.string().min(1).max(128)).min(1).max(32),
  sourceCount: z.number().int().min(1).max(32),
  riskScore: z.number().int().min(0).max(100),
  riskLevel: z.enum(["critical", "high", "medium", "low"]),
  riskReasons: z.array(textSchema).max(5),
  malware: textSchema.optional(),
  threatType: textSchema.optional(),
  confidence: z.number().finite().optional(),
  firstSeen: textSchema.optional(),
  reference: textSchema.optional()
}).strict().refine((ioc) => {
  const classified = classifyIOC(ioc.original);
  return classified.type === ioc.type && classified.normalized === ioc.normalized
    && ioc.sourceCount === ioc.sources.length && new Set(ioc.sources).size === ioc.sourceCount;
}, "Invalid normalized IOC.");
const providerSchema = z.object({
  name: z.string().min(1).max(128),
  status: z.enum(["healthy", "skipped", "error"]),
  collected: countSchema,
  byType: z.record(countSchema),
  message: textSchema.optional()
}).strict();
const retrySchema = z.object({
  batchOffset: countSchema,
  batchSize: z.number().int().min(1).max(HUNT_BATCH_LIMIT),
  failedAt: z.string().datetime(),
  message: textSchema
}).strict();
const campaignSchema = z.object({
  schemaVersion: z.literal(1),
  campaignId: z.string().uuid(),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  query: querySchema,
  iocs: z.array(iocSchema).max(HUNT_CAMPAIGN_MAX_IOCS),
  providers: z.array(providerSchema).max(32),
  stats: z.object({
    totalFetched: countSchema,
    totalAvailable: countSchema,
    excludedAtCreation: countSchema,
    truncated: countSchema
  }).strict(),
  progress: z.object({
    nextBatchOffset: countSchema,
    checked: countSchema,
    excluded: countSchema,
    completedBatches: countSchema,
    retry: retrySchema.nullable()
  }).strict()
}).strict().refine((campaign) => {
  const { stats, progress, iocs } = campaign;
  return stats.totalAvailable === iocs.length
    && stats.totalFetched === iocs.length + stats.excludedAtCreation + stats.truncated
    && progress.nextBatchOffset <= iocs.length
    && progress.checked + progress.excluded === progress.nextBatchOffset
    && progress.completedBatches <= progress.nextBatchOffset
    && (!progress.retry || (progress.retry.batchOffset === progress.nextBatchOffset
      && progress.retry.batchOffset + progress.retry.batchSize <= iocs.length))
    && Date.parse(campaign.expiresAt) === Date.parse(campaign.createdAt) + HUNT_CAMPAIGN_TTL_MS
    && new Set(iocs.map((ioc) => `${ioc.type}:${ioc.normalized}`)).size === iocs.length;
}, "Invalid campaign progress or snapshot.");
const leaseSchema = z.object({
  token: z.string().uuid(),
  expiresAt: z.number().int().min(0)
}).strict();

export type HuntCampaign = z.infer<typeof campaignSchema>;
export type HuntCampaignParams = z.infer<typeof querySchema> & { maxIocs: number; batchOffset: number };
export interface HuntCampaignBatch<T> {
  campaignId: string;
  createdAt: string;
  expiresAt: string;
  stats: HuntCampaign["stats"];
  progress: HuntCampaign["progress"];
  iocs: ThreatIntelIOC[];
  providers: ThreatIntelProviderStatus[];
  results: T[];
  batchNumber: number;
  batchOffset: number;
  batchSize: number;
  totalAvailable: number;
  nextBatchOffset: number;
  hasMore: boolean;
  retryBatchOffset: number | null;
  error?: string;
}

export async function runHuntCampaignBatch<T>(
  params: HuntCampaignParams,
  options: {
    include: (ioc: ThreatIntelIOC) => boolean;
    query: (iocs: ThreatIntelIOC[]) => Promise<T[]>;
  }
): Promise<HuntCampaignBatch<T>> {
  const query = querySchema.parse({
    indexPattern: params.indexPattern,
    timestampField: params.timestampField,
    from: params.from,
    to: params.to
  });
  if (!Number.isInteger(params.batchOffset) || params.batchOffset < 0
    || !Number.isInteger(params.maxIocs) || params.maxIocs < 1) {
    throw new Error("Invalid IOC hunt batch parameters.");
  }
  const locks = globalThis.navigator?.locks;
  if (!locks) throw new Error("IOC hunt campaign locking is unavailable.");
  return locks.request(HUNT_CAMPAIGN_KEY, { ifAvailable: true }, async (lock) => {
    if (!lock) throw new Error("An IOC hunt is already running. Retry when it finishes.");
    return withCampaignLease(async (assertOwned) => {
      let campaign: HuntCampaign;
      if (params.batchOffset === 0) {
        const collection = await collectThreatIntelSnapshot(options.include);
        const createdAt = Date.now();
        campaign = campaignSchema.parse({
          schemaVersion: 1,
          campaignId: crypto.randomUUID(),
          createdAt: new Date(createdAt).toISOString(),
          expiresAt: new Date(createdAt + HUNT_CAMPAIGN_TTL_MS).toISOString(),
          query,
          iocs: collection.iocs.slice(0, HUNT_CAMPAIGN_MAX_IOCS),
          providers: collection.providers,
          stats: {
            totalFetched: collection.totalAvailable + collection.excluded,
            totalAvailable: Math.min(collection.iocs.length, HUNT_CAMPAIGN_MAX_IOCS),
            excludedAtCreation: collection.excluded,
            truncated: Math.max(0, collection.iocs.length - HUNT_CAMPAIGN_MAX_IOCS)
          },
          progress: { nextBatchOffset: 0, checked: 0, excluded: 0, completedBatches: 0, retry: null }
        });
        boundSnapshotBytes(campaign);
        await assertOwned();
        await chrome.storage.local.set({ [HUNT_CAMPAIGN_KEY]: campaign });
      } else {
        const stored = await chrome.storage.local.get(HUNT_CAMPAIGN_KEY);
        const parsed = campaignSchema.safeParse(stored[HUNT_CAMPAIGN_KEY]);
        if (!parsed.success || snapshotBytes(parsed.data) > HUNT_CAMPAIGN_MAX_BYTES) {
          throw new Error("IOC hunt campaign is missing or invalid. Start a Fresh Scan.");
        }
        campaign = parsed.data;
        if (Date.parse(campaign.createdAt) > Date.now() || Date.parse(campaign.expiresAt) <= Date.now()) {
          throw new Error("IOC hunt campaign has expired. Start a Fresh Scan.");
        }
        if (Object.keys(query).some((key) => query[key as keyof typeof query] !== campaign.query[key as keyof typeof query])) {
          throw new Error("IOC hunt query does not match the saved campaign. Start a Fresh Scan.");
        }
        if (params.batchOffset !== campaign.progress.nextBatchOffset) {
          throw new Error(`IOC hunt offset does not match campaign progress. Retry offset ${campaign.progress.nextBatchOffset}, or start a Fresh Scan.`);
        }
      }

      const batchLimit = campaign.progress.retry?.batchSize ?? Math.min(params.maxIocs, HUNT_BATCH_LIMIT);
      // Slice first: changes to exclusions must never move later snapshot offsets.
      const selected = campaign.iocs.slice(params.batchOffset, params.batchOffset + batchLimit);
      const iocs = selected.filter(options.include);
      const batchNumber = campaign.progress.completedBatches + (selected.length > 0 ? 1 : 0);
      let results: T[] = [];
      let error: string | undefined;
      await assertOwned();
      try {
        if (iocs.length > 0) results = await options.query(structuredClone(iocs));
        if (results.length !== iocs.length) throw new Error("IOC hunt query returned an incomplete batch.");
      } catch (failure) {
        error = (failure instanceof Error ? failure.message : "IOC hunt search failed.").slice(0, 16_384);
        results = [];
      }
      await assertOwned();
      if (selected.length > 0) {
        campaign.progress = error !== undefined
          ? {
              ...campaign.progress,
              retry: { batchOffset: params.batchOffset, batchSize: selected.length, failedAt: new Date().toISOString(), message: error }
            }
          : {
              nextBatchOffset: params.batchOffset + selected.length,
              checked: campaign.progress.checked + iocs.length,
              excluded: campaign.progress.excluded + selected.length - iocs.length,
              completedBatches: campaign.progress.completedBatches + 1,
              retry: null
            };
        await chrome.storage.local.set({ [HUNT_CAMPAIGN_KEY]: campaign });
      }
      return {
        campaignId: campaign.campaignId,
        createdAt: campaign.createdAt,
        expiresAt: campaign.expiresAt,
        stats: campaign.stats,
        progress: campaign.progress,
        iocs,
        providers: campaign.providers.map(({ message, ...provider }) => ({
          ...provider,
          ...(message !== undefined ? { message } : {})
        })),
        results,
        batchNumber: Math.max(1, batchNumber),
        batchOffset: params.batchOffset,
        batchSize: selected.length,
        totalAvailable: campaign.iocs.length,
        nextBatchOffset: campaign.progress.nextBatchOffset,
        hasMore: campaign.progress.nextBatchOffset < campaign.iocs.length,
        retryBatchOffset: campaign.progress.retry?.batchOffset ?? null,
        ...(error !== undefined ? { error } : {})
      };
    });
  });
}

function snapshotBytes(campaign: HuntCampaign): number {
  return new TextEncoder().encode(JSON.stringify(campaign)).byteLength;
}

function boundSnapshotBytes(campaign: HuntCampaign): void {
  // Reserve space for progress/retry metadata within the persisted document's bound.
  const budget = HUNT_CAMPAIGN_MAX_BYTES - 32_768;
  if (snapshotBytes(campaign) <= budget) return;
  const iocs = campaign.iocs;
  let low = 0;
  let high = iocs.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    campaign.iocs = iocs.slice(0, middle);
    if (snapshotBytes(campaign) <= budget) low = middle;
    else high = middle - 1;
  }
  campaign.iocs = iocs.slice(0, low);
  campaign.stats.truncated += iocs.length - low;
  campaign.stats.totalAvailable = low;
  if (snapshotBytes(campaign) > budget) throw new Error("IOC hunt campaign metadata exceeds its storage limit.");
}

async function withCampaignLease<T>(operation: (assertOwned: () => Promise<void>) => Promise<T>): Promise<T> {
  const stored = await chrome.storage.local.get(HUNT_CAMPAIGN_LEASE_KEY);
  const existing = leaseSchema.safeParse(stored[HUNT_CAMPAIGN_LEASE_KEY]);
  if (existing.success && existing.data.expiresAt > Date.now()) {
    throw new Error("An IOC hunt is already running. Retry after its busy lease expires.");
  }
  const token = crypto.randomUUID();
  const writeLease = () => chrome.storage.local.set({
    [HUNT_CAMPAIGN_LEASE_KEY]: { token, expiresAt: Date.now() + HUNT_CAMPAIGN_LEASE_MS }
  });
  await writeLease();
  let leaseFailed = false;
  const assertOwned = async () => {
    const current = await chrome.storage.local.get(HUNT_CAMPAIGN_LEASE_KEY);
    const lease = leaseSchema.safeParse(current[HUNT_CAMPAIGN_LEASE_KEY]);
    if (leaseFailed || !lease.success || lease.data.token !== token || lease.data.expiresAt <= Date.now()) {
      throw new Error("IOC hunt busy lease was lost. Retry the saved campaign offset.");
    }
  };
  let renewal = Promise.resolve();
  const timer = setInterval(() => {
    renewal = renewal.then(async () => {
      await assertOwned();
      await writeLease();
    }).catch(() => { leaseFailed = true; });
  }, HUNT_CAMPAIGN_LEASE_MS / 4);
  try {
    return await operation(assertOwned);
  } finally {
    clearInterval(timer);
    await renewal;
    try {
      const current = await chrome.storage.local.get(HUNT_CAMPAIGN_LEASE_KEY);
      if (leaseSchema.safeParse(current[HUNT_CAMPAIGN_LEASE_KEY]).data?.token === token) {
        await chrome.storage.local.remove(HUNT_CAMPAIGN_LEASE_KEY);
      }
    } catch {
      // A failed cleanup expires naturally; do not hide a committed batch result.
    }
  }
}
