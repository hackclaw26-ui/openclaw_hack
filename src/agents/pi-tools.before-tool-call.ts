import type { AnyAgentTool } from "./tools/common.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { getGlobalHookRunner } from "../plugins/hook-runner-global.js";
import { normalizeToolName } from "./tool-policy.js";

type HookContext = {
  agentId?: string;
  sessionKey?: string;
};

type HookOutcome = { blocked: true; reason: string } | { blocked: false; params: unknown };

const log = createSubsystemLogger("agents/tools");

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function runBeforeToolCallHook(args: {
  toolName: string;
  params: unknown;
  toolCallId?: string;
  ctx?: HookContext;
}): Promise<HookOutcome> {
  const hookRunner = getGlobalHookRunner();
  if (!hookRunner?.hasHooks("before_tool_call")) {
    return { blocked: false, params: args.params };
  }

  const toolName = normalizeToolName(args.toolName || "tool");
  const params = args.params;
  try {
    const normalizedParams = isPlainObject(params) ? params : {};
    const hookResult = await hookRunner.runBeforeToolCall(
      {
        toolName,
        params: normalizedParams,
      },
      {
        toolName,
        agentId: args.ctx?.agentId,
        sessionKey: args.ctx?.sessionKey,
      },
    );

    if (hookResult?.block) {
      return {
        blocked: true,
        reason: hookResult.blockReason || "Tool call blocked by plugin hook",
      };
    }

    if (hookResult?.params && isPlainObject(hookResult.params)) {
      if (isPlainObject(params)) {
        return { blocked: false, params: { ...params, ...hookResult.params } };
      }
      return { blocked: false, params: hookResult.params };
    }
  } catch (err) {
    const toolCallId = args.toolCallId ? ` toolCallId=${args.toolCallId}` : "";
    log.warn(`before_tool_call hook failed: tool=${toolName}${toolCallId} error=${String(err)}`);
  }

  return { blocked: false, params };
}

type AfterHookOutcome = { blocked: true; reason: string } | { blocked: false };

/**
 * Run after_tool_call plugin hooks. Returns a block verdict when a guardrail
 * flags the tool result (e.g. sensitive data in the output).
 */
export async function runAfterToolCallHook(args: {
  toolName: string;
  params: unknown;
  result?: unknown;
  error?: string;
  durationMs?: number;
  toolCallId?: string;
  ctx?: HookContext;
}): Promise<AfterHookOutcome> {
  const hookRunner = getGlobalHookRunner();
  if (!hookRunner?.hasHooks("after_tool_call")) {
    return { blocked: false };
  }

  const toolName = normalizeToolName(args.toolName || "tool");
  const params = isPlainObject(args.params) ? args.params : {};

  try {
    const hookResult = await hookRunner.runAfterToolCall(
      {
        toolName,
        params,
        result: args.result,
        error: args.error,
        durationMs: args.durationMs,
      },
      {
        toolName,
        agentId: args.ctx?.agentId,
        sessionKey: args.ctx?.sessionKey,
      },
    );

    if (hookResult?.block) {
      return {
        blocked: true,
        reason: hookResult.blockReason || "Tool result blocked by plugin hook",
      };
    }
  } catch (err) {
    const toolCallId = args.toolCallId ? ` toolCallId=${args.toolCallId}` : "";
    log.warn(`after_tool_call hook failed: tool=${toolName}${toolCallId} error=${String(err)}`);
  }

  return { blocked: false };
}

export function wrapToolWithBeforeToolCallHook(
  tool: AnyAgentTool,
  ctx?: HookContext,
): AnyAgentTool {
  const execute = tool.execute;
  if (!execute) {
    return tool;
  }
  const toolName = tool.name || "tool";
  return {
    ...tool,
    execute: async (toolCallId, params, signal, onUpdate) => {
      // --- before_tool_call: may block or modify params ---
      const beforeOutcome = await runBeforeToolCallHook({
        toolName,
        params,
        toolCallId,
        ctx,
      });
      if (beforeOutcome.blocked) {
        throw new Error(beforeOutcome.reason);
      }

      // --- execute the tool ---
      const start = Date.now();
      let result: Awaited<ReturnType<typeof execute>>;
      let error: string | undefined;
      try {
        result = await execute(toolCallId, beforeOutcome.params, signal, onUpdate);
      } catch (err) {
        error = String(err);
        // Run after hook even on errors so guardrails can observe failures
        await runAfterToolCallHook({
          toolName,
          params: beforeOutcome.params as Record<string, unknown>,
          error,
          durationMs: Date.now() - start,
          toolCallId,
          ctx,
        });
        throw err;
      }

      // --- after_tool_call: may block the result ---
      const afterOutcome = await runAfterToolCallHook({
        toolName,
        params: beforeOutcome.params as Record<string, unknown>,
        result,
        durationMs: Date.now() - start,
        toolCallId,
        ctx,
      });
      if (afterOutcome.blocked) {
        throw new Error(afterOutcome.reason);
      }

      return result;
    },
  };
}

export const __testing = {
  runBeforeToolCallHook,
  runAfterToolCallHook,
  isPlainObject,
};
