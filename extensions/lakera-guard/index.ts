/**
 * Lakera Guard plugin for OpenClaw.
 *
 * Registers a `before_tool_call` hook that screens every tool call through
 * the Lakera Guard API. If the call is flagged (prompt injection, jailbreak,
 * PII leak, etc.) the tool call is blocked before execution.
 *
 * Configuration (via `openclaw config set plugins.entries.lakera-guard`):
 *   apiKey      – (required) Lakera Guard API key
 *   projectId   – (optional) Lakera project ID for a specific policy
 *   endpoint    – (optional) override API URL
 *   mode        – "block" (default) or "log" (warn but allow)
 *   timeoutMs   – HTTP timeout (default 5 000 ms)
 *   skipTools   – array of tool names excluded from screening
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { screenContent, summarizeVerdict } from "./src/lakera-client.js";
import type { LakeraGuardConfig } from "./src/lakera-client.js";

type PluginConfig = {
  apiKey: string;
  projectId?: string;
  endpoint?: string;
  mode?: "block" | "log";
  timeoutMs?: number;
  skipTools?: string[];
};

function resolveConfig(raw?: Record<string, unknown>): PluginConfig | null {
  if (!raw || typeof raw.apiKey !== "string" || raw.apiKey.length === 0) {
    return null;
  }
  return {
    apiKey: raw.apiKey as string,
    projectId: typeof raw.projectId === "string" ? raw.projectId : undefined,
    endpoint: typeof raw.endpoint === "string" ? raw.endpoint : undefined,
    mode: raw.mode === "log" ? "log" : "block",
    timeoutMs: typeof raw.timeoutMs === "number" ? raw.timeoutMs : undefined,
    skipTools: Array.isArray(raw.skipTools)
      ? (raw.skipTools as string[]).filter((s) => typeof s === "string")
      : undefined,
  };
}

const lakeraGuardPlugin = {
  id: "lakera-guard",
  name: "Lakera Guard",
  description:
    "Screens tool calls through the Lakera Guard API to block prompt injection, jailbreaks, and other threats.",

  register(api: OpenClawPluginApi) {
    const cfg = resolveConfig(api.pluginConfig);

    if (!cfg) {
      api.logger.warn(
        "Lakera Guard plugin loaded but no apiKey configured – guardrail is inactive. " +
          'Set plugins.entries.lakera-guard.apiKey via "openclaw config set".',
      );
      return;
    }

    const skipSet = new Set(cfg.skipTools ?? []);
    const mode = cfg.mode ?? "block";

    const lakeraConfig: LakeraGuardConfig = {
      apiKey: cfg.apiKey,
      endpoint: cfg.endpoint,
      projectId: cfg.projectId,
      timeoutMs: cfg.timeoutMs,
    };

    api.logger.info(`Lakera Guard active (mode=${mode}, skipTools=[${[...skipSet].join(",")}])`);

    // -----------------------------------------------------------------------
    // before_tool_call hook – runs before every tool execution
    // -----------------------------------------------------------------------
    api.on(
      "before_tool_call",
      async (event, ctx) => {
        const { toolName, params } = event;

        // Allow explicitly skipped tools through without screening
        if (skipSet.has(toolName)) {
          return;
        }

        try {
          const verdict = await screenContent(lakeraConfig, toolName, params);
          const summary = summarizeVerdict(verdict);

          if (verdict.flagged) {
            const logMsg =
              `Lakera Guard flagged tool call: tool=${toolName} ` +
              `session=${ctx.sessionKey ?? "?"} verdict=${summary} ` +
              `request=${verdict.metadata?.request_uuid ?? "?"}`;

            if (mode === "block") {
              api.logger.warn(`${logMsg} → BLOCKED`);
              return {
                block: true,
                blockReason:
                  `Tool call blocked by Lakera Guard (${summary}). ` +
                  "The request was identified as potentially malicious.",
              };
            }

            // log-only mode
            api.logger.warn(`${logMsg} → ALLOWED (log-only mode)`);
          }
        } catch (err) {
          // On network / API errors, fail open but log a warning so operators
          // can investigate. Switch to `block` + throw if you prefer fail-closed.
          api.logger.error(
            `Lakera Guard screening failed for tool=${toolName}: ${String(err)} – allowing execution (fail-open)`,
          );
        }

        // Not flagged (or fail-open) – proceed normally
        return undefined;
      },
      // Run with high priority so this guardrail executes before other hooks
      { priority: 1000 },
    );
  },
};

export default lakeraGuardPlugin;
