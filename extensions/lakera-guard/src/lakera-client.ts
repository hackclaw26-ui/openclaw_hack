/**
 * Lakera Guard v2 API client.
 *
 * Screens content (tool call params serialized as a user message) and returns
 * a typed verdict so the caller can decide whether to block.
 */

export type LakeraGuardConfig = {
  apiKey: string;
  endpoint?: string;
  projectId?: string;
  timeoutMs?: number;
};

export type LakeraPayloadItem = {
  start?: number;
  end?: number;
  text?: string;
  detector_type?: string;
  labels?: string[];
  message_id?: number;
};

export type LakeraBreakdownItem = {
  project_id?: string;
  policy_id?: string;
  detector_id?: string;
  detector_type?: string;
  detected: boolean;
  message_id?: number;
};

export type LakeraGuardResponse = {
  flagged: boolean | null;
  payload?: LakeraPayloadItem[] | null;
  breakdown?: LakeraBreakdownItem[] | null;
  metadata?: { request_uuid?: string } | null;
};

const DEFAULT_ENDPOINT = "https://api.lakera.ai/v2/guard";
const DEFAULT_TIMEOUT_MS = 5_000;

/**
 * Call the Lakera Guard `/v2/guard` endpoint.
 *
 * The tool call is represented as a conversation: a system message describing
 * the context ("tool call screening") plus a user message containing the
 * serialized tool name + parameters. This lets Lakera's prompt-injection and
 * content detectors inspect the payload.
 */
export async function screenContent(
  cfg: LakeraGuardConfig,
  toolName: string,
  params: Record<string, unknown>,
): Promise<LakeraGuardResponse> {
  const endpoint = cfg.endpoint || DEFAULT_ENDPOINT;
  const timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const body: Record<string, unknown> = {
    messages: [
      {
        role: "tool",
        content: `Tool: ${toolName}\nParameters: ${JSON.stringify(params)}`,
      },
    ],
    // Ask for full breakdown so logs are useful for debugging
    breakdown: true,
    payload: true,
  };

  if (cfg.projectId) {
    body.project_id = cfg.projectId;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${cfg.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "(no body)");
      throw new Error(`Lakera Guard API returned HTTP ${res.status}: ${text}`);
    }

    return (await res.json()) as LakeraGuardResponse;
  } finally {
    clearTimeout(timer);
  }
}

/** Build a human-readable summary from a Lakera Guard response. */
export function summarizeVerdict(resp: LakeraGuardResponse): string {
  if (!resp.flagged) {
    return "clean";
  }

  const detectors =
    resp.breakdown
      ?.filter((b) => b.detected)
      .map((b) => b.detector_type ?? b.detector_id ?? "unknown") ?? [];

  const labels = resp.payload?.flatMap((p) => p.labels ?? []) ?? [];
  const unique = [...new Set([...detectors, ...labels])];

  return unique.length > 0 ? `flagged (${unique.join(", ")})` : "flagged";
}
