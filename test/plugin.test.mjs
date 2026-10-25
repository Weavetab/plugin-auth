import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import os from "node:os";

import plugin, {
  authPlugin,
  saveProfile,
  loadProfile,
  listProfiles,
  deleteProfile,
  captureSession,
  injectSession,
} from "../dist/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(join(__dirname, "..", "weavetab.json"), "utf-8"));
const testVaultDir = join(os.tmpdir(), `weavetab-auth-test-${Date.now()}`);

function makeMockContext() {
  const tools = new Map();
  const ctx = {
    name: plugin.name,
    config: { vaultDir: testVaultDir },
    mcp: {
      registerTool: (t) => {
        tools.set(t.name, t);
      },
    },
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
  };
  return { ctx, tools };
}

describe("@weavetab/plugin-auth", () => {
  before(() => {
    // clean slate
  });

  after(() => {
    try {
      if (existsSync(testVaultDir)) {
        rmSync(testVaultDir, { recursive: true, force: true });
      }
    } catch {
      // tmpdir cleanup best effort
    }
  });

  it("exposes valid plugin definition", () => {
    assert.equal(authPlugin, plugin);
    assert.equal(plugin.name, "@weavetab/plugin-auth");
    assert.equal(plugin.version, "1.0.1");
    assert.equal(typeof plugin.onLoad, "function");
    assert.equal(typeof plugin.onUnload, "function");
  });

  it("ships manifest with expected tools and declared permissions", () => {
    assert.equal(manifest.name, "@weavetab/plugin-auth");
    assert.equal(manifest.entry, "dist/index.js");

    for (const [key, val] of Object.entries(manifest.permissions)) {
      if (val && typeof val === "object" && "reason" in val) {
        assert.equal(typeof val.reason, "string");
        assert.ok(val.reason.length > 0);
      }
    }

    const toolNames = manifest.tools.map((t) => t.name);
    assert.deepEqual(toolNames, [
      "plugin_auth_capture",
      "plugin_auth_inject",
      "plugin_auth_list",
      "plugin_auth_delete",
    ]);
  });

  it("registers all four tools during onLoad", async () => {
    const { ctx, tools } = makeMockContext();
    await plugin.onLoad(ctx);

    assert.equal(tools.size, 4);
    assert.ok(tools.has("plugin_auth_capture"));
    assert.ok(tools.has("plugin_auth_inject"));
    assert.ok(tools.has("plugin_auth_list"));
    assert.ok(tools.has("plugin_auth_delete"));
  });

  it("encrypts and decrypts session profiles via AES-256-GCM at rest", async () => {
    const sampleProfile = {
      version: 1,
      service: "github-test",
      domain: "github.com",
      origin: "https://github.com",
      capturedAt: new Date().toISOString(),
      cookies: [
        {
          name: "user_session",
          value: "super_secret_cookie_token_999",
          domain: ".github.com",
          path: "/",
          httpOnly: true,
          secure: true,
        },
      ],
      localStorage: {
        "gh:user": "fy2ne",
      },
    };

    const saved = await saveProfile(sampleProfile, testVaultDir);
    assert.ok(saved.file.endsWith(".enc"));

    const rawFile = readFileSync(saved.path, "utf-8");
    assert.ok(!rawFile.includes("super_secret_cookie_token_999"), "raw token must not be plaintext on disk");

    const loaded = await loadProfile("github-test", testVaultDir);
    assert.ok(loaded);
    assert.equal(loaded.service, "github-test");
    assert.equal(loaded.cookies.length, 1);
    assert.equal(loaded.cookies[0].value, "super_secret_cookie_token_999");
    assert.equal(loaded.localStorage["gh:user"], "fy2ne");

    const list = await listProfiles(testVaultDir);
    assert.equal(list.length, 1);
    assert.equal(list[0].service, "github-test");
    assert.equal(list[0].cookieCount, 1);

    const deleted = await deleteProfile("github-test", testVaultDir);
    assert.equal(deleted, true);

    const afterDelete = await loadProfile("github-test", testVaultDir);
    assert.equal(afterDelete, null);
  });

  it("captures active tab without leaking cookie secrets in result", async () => {
    const mockSession = {
      Page: {
        getFrameTree: async () => ({
          frameTree: { frame: { url: "https://stripe.com/dashboard" } },
        }),
      },
      Network: {
        getCookies: async () => ({
          cookies: [
            {
              name: "merchant_session",
              value: "secret_merchant_token_777",
              domain: ".stripe.com",
              path: "/",
            },
          ],
        }),
      },
      Runtime: {
        evaluate: async () => ({
          result: { value: { ls: { account_id: "acct_123" }, ss: {} } },
        }),
      },
    };

    const res = await captureSession(mockSession, { vaultDir: testVaultDir });
    assert.equal(res.success, true);
    assert.equal(res.service, "stripe");
    assert.equal(res.cookieCount, 1);
    assert.equal(res.storageKeyCount, 1);

    // CRITICAL: verify zero credential leakage in tool response
    const dumped = JSON.stringify(res);
    assert.ok(!dumped.includes("secret_merchant_token_777"), "secrets must never leak in capture result");
  });

  it("injects session cookies directly over CDP without token leakage", async () => {
    let cookiesInjected = null;
    let navigatedTo = null;

    const mockSession = {
      Network: {
        setCookies: async (params) => {
          cookiesInjected = params.cookies;
        },
      },
      Page: {
        navigate: async ({ url }) => {
          navigatedTo = url;
        },
        loadEventFired: async () => {},
      },
      Runtime: {
        evaluate: async () => {},
      },
    };

    const res = await injectSession(mockSession, { service: "stripe", vaultDir: testVaultDir });
    assert.equal(res.success, true);
    assert.equal(res.authenticated, true);
    assert.equal(res.cookiesInjected, 1);
    assert.equal(navigatedTo, "https://stripe.com");

    assert.ok(cookiesInjected && cookiesInjected.length === 1);
    assert.equal(cookiesInjected[0].value, "secret_merchant_token_777");

    const dumped = JSON.stringify(res);
    assert.ok(!dumped.includes("secret_merchant_token_777"), "secrets must never leak in inject result");
  });
});
