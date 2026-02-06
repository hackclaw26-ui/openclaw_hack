import { describe, expect, it, vi, beforeEach } from "vitest";
import { screenContent, summarizeVerdict } from "./src/lakera-client.js";
import type { LakeraGuardResponse } from "./src/lakera-client.js";

// ---------------------------------------------------------------------------
// Lakera client unit tests
// ---------------------------------------------------------------------------

describe("lakera-client", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("screenContent", () => {
    it("sends correct request shape and returns parsed response", async () => {
      const mockResponse: LakeraGuardResponse = {
        flagged: false,
        breakdown: [],
        payload: [],
        metadata: { request_uuid: "test-uuid" },
      };

      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response(JSON.stringify(mockResponse), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );

      const result = await screenContent(
        { apiKey: "sk_test_123" },
        "bash",
        { command: "ls -la" },
      );

      expect(result.flagged).toBe(false);

      const call = vi.mocked(globalThis.fetch).mock.calls[0]!;
      expect(call[0]).toBe("https://api.lakera.ai/v2/guard");

      const init = call[1] as RequestInit;
      expect(init.headers).toEqual(
        expect.objectContaining({
          Authorization: "Bearer sk_test_123",
          "Content-Type": "application/json",
        }),
      );

      const body = JSON.parse(init.body as string);
      expect(body.messages).toHaveLength(2);
      expect(body.messages[1].role).toBe("user");
      expect(body.messages[1].content).toContain("bash");
      expect(body.messages[1].content).toContain("ls -la");
      expect(body.breakdown).toBe(true);
      expect(body.payload).toBe(true);
    });

    it("includes projectId when configured", async () => {
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response(JSON.stringify({ flagged: false }), { status: 200 }),
      );

      await screenContent(
        { apiKey: "sk_test", projectId: "proj_abc" },
        "web_fetch",
        { url: "https://example.com" },
      );

      const body = JSON.parse(
        (vi.mocked(globalThis.fetch).mock.calls[0]![1] as RequestInit).body as string,
      );
      expect(body.project_id).toBe("proj_abc");
    });

    it("throws on non-200 responses", async () => {
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response("Unauthorized", { status: 401 }),
      );

      await expect(
        screenContent({ apiKey: "bad_key" }, "bash", { command: "rm -rf /" }),
      ).rejects.toThrow("Lakera Guard API returned HTTP 401");
    });

    it("respects custom endpoint", async () => {
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response(JSON.stringify({ flagged: false }), { status: 200 }),
      );

      await screenContent(
        { apiKey: "sk_test", endpoint: "https://custom.lakera.test/v2/guard" },
        "tool",
        {},
      );

      expect(vi.mocked(globalThis.fetch).mock.calls[0]![0]).toBe(
        "https://custom.lakera.test/v2/guard",
      );
    });
  });

  describe("summarizeVerdict", () => {
    it("returns clean for non-flagged responses", () => {
      expect(summarizeVerdict({ flagged: false })).toBe("clean");
      expect(summarizeVerdict({ flagged: null })).toBe("clean");
    });

    it("returns detector types for flagged responses", () => {
      const resp: LakeraGuardResponse = {
        flagged: true,
        breakdown: [
          { detector_type: "prompt_injection", detected: true },
          { detector_type: "pii", detected: false },
          { detector_type: "jailbreak", detected: true },
        ],
        payload: [],
      };
      const summary = summarizeVerdict(resp);
      expect(summary).toContain("prompt_injection");
      expect(summary).toContain("jailbreak");
      expect(summary).not.toContain("pii");
    });

    it("includes payload labels", () => {
      const resp: LakeraGuardResponse = {
        flagged: true,
        payload: [{ labels: ["ssn", "email"] }],
        breakdown: [],
      };
      const summary = summarizeVerdict(resp);
      expect(summary).toContain("ssn");
      expect(summary).toContain("email");
    });

    it("deduplicates detector types and labels", () => {
      const resp: LakeraGuardResponse = {
        flagged: true,
        breakdown: [
          { detector_type: "prompt_injection", detected: true },
          { detector_type: "prompt_injection", detected: true },
        ],
        payload: [{ labels: ["prompt_injection"] }],
      };
      const summary = summarizeVerdict(resp);
      // Should only appear once
      const matches = summary.match(/prompt_injection/g);
      expect(matches).toHaveLength(1);
    });

    it("returns generic flagged when no details available", () => {
      expect(summarizeVerdict({ flagged: true })).toBe("flagged");
    });
  });
});

// ---------------------------------------------------------------------------
// Plugin hook integration tests (mock the Lakera API)
// ---------------------------------------------------------------------------

describe("lakera-guard plugin", () => {
  // Minimal mock of the plugin API to exercise register()
  function createMockApi(pluginConfig: Record<string, unknown>) {
    const hooks: Array<{
      name: string;
      handler: (event: unknown, ctx: unknown) => unknown;
      opts?: { priority?: number };
    }> = [];

    const api = {
      id: "lakera-guard",
      name: "Lakera Guard",
      pluginConfig,
      logger: {
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        debug: vi.fn(),
      },
      on: vi.fn((name: string, handler: (e: unknown, c: unknown) => unknown, opts?: { priority?: number }) => {
        hooks.push({ name, handler, opts });
      }),
    };

    return { api, hooks };
  }

  it("warns and does nothing when apiKey is missing", async () => {
    const { api } = createMockApi({});
    const mod = await import("./index.js");
    mod.default.register(api as never);
    expect(api.logger.warn).toHaveBeenCalledWith(expect.stringContaining("no apiKey"));
    expect(api.on).not.toHaveBeenCalled();
  });

  it("registers before_tool_call hook with high priority", async () => {
    const { api, hooks } = createMockApi({ apiKey: "sk_test" });
    const mod = await import("./index.js");
    mod.default.register(api as never);
    expect(hooks).toHaveLength(1);
    expect(hooks[0]!.name).toBe("before_tool_call");
    expect(hooks[0]!.opts?.priority).toBe(1000);
  });

  it("blocks flagged tool calls in block mode", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          flagged: true,
          breakdown: [{ detector_type: "prompt_injection", detected: true }],
          payload: [],
          metadata: { request_uuid: "req-1" },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const { api, hooks } = createMockApi({ apiKey: "sk_test", mode: "block" });
    const mod = await import("./index.js");
    mod.default.register(api as never);

    const handler = hooks[0]!.handler;
    const result = await handler(
      { toolName: "bash", params: { command: "ignore previous instructions" } },
      { toolName: "bash", agentId: "agent-1", sessionKey: "sess-1" },
    );

    expect(result).toEqual(
      expect.objectContaining({ block: true, blockReason: expect.stringContaining("Lakera Guard") }),
    );
  });

  it("allows flagged tool calls in log mode", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          flagged: true,
          breakdown: [{ detector_type: "prompt_injection", detected: true }],
          payload: [],
        }),
        { status: 200 },
      ),
    );

    const { api, hooks } = createMockApi({ apiKey: "sk_test", mode: "log" });
    const mod = await import("./index.js");
    mod.default.register(api as never);

    const result = await hooks[0]!.handler(
      { toolName: "bash", params: { command: "bad stuff" } },
      { toolName: "bash" },
    );

    // Should not block
    expect(result).toBeUndefined();
    // But should log
    expect(api.logger.warn).toHaveBeenCalledWith(expect.stringContaining("ALLOWED"));
  });

  it("skips screening for tools in skipTools", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const { api, hooks } = createMockApi({ apiKey: "sk_test", skipTools: ["read_file"] });
    const mod = await import("./index.js");
    mod.default.register(api as never);

    const result = await hooks[0]!.handler(
      { toolName: "read_file", params: { path: "/etc/passwd" } },
      { toolName: "read_file" },
    );

    expect(result).toBeUndefined();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("fails open on network errors", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("ECONNREFUSED"));

    const { api, hooks } = createMockApi({ apiKey: "sk_test" });
    const mod = await import("./index.js");
    mod.default.register(api as never);

    const result = await hooks[0]!.handler(
      { toolName: "bash", params: { command: "echo hi" } },
      { toolName: "bash" },
    );

    expect(result).toBeUndefined();
    expect(api.logger.error).toHaveBeenCalledWith(expect.stringContaining("fail-open"));
  });
});
