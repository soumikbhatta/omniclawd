import fs from "node:fs/promises";
import { describe, it, expect, vi, afterEach } from "vitest";
import { loadWorkspaceBootstrapFiles, DEFAULT_TOOLS_FILENAME } from "./workspace.js";

// Mock resolveUserPath to just return the path as-is
vi.mock("../utils.js", () => ({
  resolveUserPath: (p: string) => p,
}));

describe("workspace security", () => {
  const workspaceDir = "/abs/path/to/test-workspace";

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("redacts OpenAI API keys from TOOLS.md", async () => {
    const leak = "sk-ant-1234567890abcdef1234567890abcdef";
    const content = `
# My Tools
Here is my secret key: ${leak}
Don't tell anyone!
    `;

    vi.spyOn(fs, "readFile").mockImplementation(async (filePath) => {
      // @ts-ignore
      if (typeof filePath === "string" && filePath.endsWith(DEFAULT_TOOLS_FILENAME)) {
        return content;
      }
      throw new Error("File not found: " + filePath);
    });

    vi.spyOn(fs, "access").mockResolvedValue(undefined);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const files = await loadWorkspaceBootstrapFiles(workspaceDir);
    const toolsFile = files.find((f) => f.name === DEFAULT_TOOLS_FILENAME);

    expect(toolsFile).toBeDefined();
    // Verify content is present (not missing)
    expect(toolsFile?.missing).toBe(false);
    expect(toolsFile?.content).toBeDefined();

    expect(toolsFile?.content).not.toContain(leak);
    expect(toolsFile?.content).toContain("REDACTED");
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("Secrets detected in TOOLS.md"));
  });

  it("redacts GitHub tokens", async () => {
    const leak = "ghp_1234567890abcdef1234567890abcdef";
    const content = `Token: ${leak}`;

    vi.spyOn(fs, "readFile").mockImplementation(async (filePath) => {
      // @ts-ignore
      if (typeof filePath === "string" && filePath.endsWith(DEFAULT_TOOLS_FILENAME)) {
        return content;
      }
      throw new Error("File not found");
    });
    vi.spyOn(fs, "access").mockResolvedValue(undefined);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const files = await loadWorkspaceBootstrapFiles(workspaceDir);
    const toolsFile = files.find((f) => f.name === DEFAULT_TOOLS_FILENAME);

    expect(toolsFile?.missing).toBe(false);
    expect(toolsFile?.content).not.toContain(leak);
    expect(toolsFile?.content).toContain("REDACTED");
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("Secrets detected in TOOLS.md"));
  });

  it("does not warn on safe content", async () => {
    const content = "# My Tools\nJust some normal text here.";

    vi.spyOn(fs, "readFile").mockImplementation(async (filePath) => {
      // @ts-ignore
      if (typeof filePath === "string" && filePath.endsWith(DEFAULT_TOOLS_FILENAME)) {
        return content;
      }
      throw new Error("File not found");
    });
    vi.spyOn(fs, "access").mockResolvedValue(undefined);
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const files = await loadWorkspaceBootstrapFiles(workspaceDir);
    const toolsFile = files.find((f) => f.name === DEFAULT_TOOLS_FILENAME);

    expect(toolsFile?.content).toBe(content);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
