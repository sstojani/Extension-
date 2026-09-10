import type { ClassifiedIOC } from "@soc-watch/ioc";
import type { IOCFieldMapping } from "@soc-watch/protocol";

export interface IOCSearchBodyParams {
  ioc: ClassifiedIOC;
  fieldMapping: IOCFieldMapping;
  timestampField: string;
  from: string;
  to: string;
  size: number;
}

export interface IOCBulkSearchBodyParams {
  iocs: ClassifiedIOC[];
  timestampField: string;
  from: string;
  to: string;
  size: number;
}

export function buildIOCSearchBody(params: IOCSearchBodyParams) {
  const fields = params.fieldMapping[params.ioc.type as keyof IOCFieldMapping] ?? [];
  return {
    size: params.size,
    track_total_hits: true,
    sort: [{ [params.timestampField]: { order: "desc" } }],
    query: {
      bool: {
        filter: [
          {
            range: {
              [params.timestampField]: {
                gte: params.from,
                lte: params.to
              }
            }
          },
          {
            bool: {
              should: fields.map((field) => ({ term: { [field]: params.ioc.normalized } })),
              minimum_should_match: 1
            }
          }
        ]
      }
    },
    _source: {
      excludes: ["*.access_api_key", "*.access_api_key_id", "kibana.cookie", "authorization"]
    }
  };
}

const DEFAULT_IOC_FIELDS: Record<string, string[]> = {
  ip: ["source.ip", "destination.ip", "client.ip", "server.ip", "host.ip"],
  domain: ["url.domain", "dns.question.name", "destination.domain"],
  url: ["url.full", "url.original"],
  md5: ["file.hash.md5"],
  sha1: ["file.hash.sha1"],
  sha256: ["file.hash.sha256"]
};

export function buildIOCBulkSearchBody(params: IOCBulkSearchBodyParams) {
  const fieldValues = new Map<string, Set<string>>();
  for (const ioc of params.iocs) {
    for (const field of DEFAULT_IOC_FIELDS[ioc.type] ?? []) {
      const values = fieldValues.get(field) ?? new Set<string>();
      values.add(ioc.normalized);
      fieldValues.set(field, values);
    }
  }

  const matchAnyField = [...fieldValues.entries()].map(([field, values]) => ({
    terms: { [field]: [...values] }
  }));
  const filters = Object.fromEntries(params.iocs.map((ioc, index) => {
    const fields = DEFAULT_IOC_FIELDS[ioc.type] ?? [];
    return [`ioc_${index}`, {
      bool: {
        should: fields.map((field) => ({ term: { [field]: ioc.normalized } })),
        minimum_should_match: 1
      }
    }];
  }));

  return {
    size: 0,
    track_total_hits: true,
    timeout: "45s",
    query: {
      bool: {
        filter: [
          { range: { [params.timestampField]: { gte: params.from, lte: params.to } } },
          { bool: { should: matchAnyField, minimum_should_match: 1 } }
        ]
      }
    },
    aggs: {
      ioc_matches: {
        filters: { filters },
        aggs: {
          latest: {
            top_hits: {
              size: params.size,
              sort: [{ [params.timestampField]: { order: "desc" } }],
              _source: {
                excludes: ["*.access_api_key", "*.access_api_key_id", "kibana.cookie", "authorization"]
              }
            }
          }
        }
      }
    }
  };
}
