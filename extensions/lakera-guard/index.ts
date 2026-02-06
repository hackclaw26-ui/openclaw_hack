/**
 * Lakera Guard plugin for OpenClaw.
 *
 * Registers two hooks:
 *   1. `before_tool_call` – screens every tool call *before* execution.
 *      Catches prompt injection, jailbreak attempts, etc. in tool parameters.
 *   2. `after_tool_call`  – screens every tool result *after* execution.
 *      Catches PII leaks, data exfiltration, and malicious content in outputs.
 *
 * In both cases, flagged calls/results are blocked (or logged, depending on
 * the configured mode).
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
import { screenContent, screenToolResult, summarizeVerdict } from "./src/lakera-client.js";
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
    "Screens tool calls and their results through the Lakera Guard API to block prompt injection, jailbreaks, PII leaks, and other threats.",

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

    // -----------------------------------------------------------------------
    // after_tool_call hook – runs after every tool execution to screen output
    // -----------------------------------------------------------------------
    api.on(
      "after_tool_call",
      async (event, ctx) => {
        const { toolName, params, result, error } = event;

        // Allow explicitly skipped tools through without screening
        if (skipSet.has(toolName)) {
          return;
        }

        // Skip screening when the tool itself errored – nothing sensitive to leak
        if (error && !result) {
          return;
        }

        try {
          const verdict = await screenToolResult(lakeraConfig, toolName, params, result, error);
          const summary = summarizeVerdict(verdict);

          if (verdict.flagged) {
            const logMsg =
              `Lakera Guard flagged tool result: tool=${toolName} ` +
              `session=${ctx.sessionKey ?? "?"} verdict=${summary} ` +
              `request=${verdict.metadata?.request_uuid ?? "?"}`;

            if (mode === "block") {
              api.logger.warn(`${logMsg} → BLOCKED`);
              return {
                block: true,
                blockReason:
                  `Tool result blocked by Lakera Guard (${summary}). ` +
                  "The tool output was identified as potentially containing sensitive or malicious content.",
              };
            }

            // log-only mode
            api.logger.warn(`${logMsg} → ALLOWED (log-only mode)`);
          }
        } catch (err) {
          // Fail open on API errors – log a warning for operators.
          api.logger.error(
            `Lakera Guard result screening failed for tool=${toolName}: ${String(err)} – allowing result (fail-open)`,
          );
        }

        return undefined;
      },
      // Same high priority as the before hook
      { priority: 1000 },
    );
  },
};

export default lakeraGuardPlugin;
