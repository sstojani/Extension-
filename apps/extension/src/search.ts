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
