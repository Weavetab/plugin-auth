import { definePlugin, defineTool, z, type PluginContext } from "@weavetab/sdk";
import { captureSession } from "./capture.js";
import { injectSession } from "./inject.js";
import { listProfiles, deleteProfile } from "./vault.js";

export * from "./types.js";
export * from "./vault.js";
export * from "./capture.js";
export * from "./inject.js";

export const authPlugin = definePlugin({
  name: "@weavetab/plugin-auth",
  version: "1.0.0",
  description: "Zero-Leak Enterprise Session & Cookie Vault for Weavetab.",

  defaultConfig: {
    vaultDir: "",
    defaultNavigate: true,
    includeStorage: true,
  },

  async onLoad(ctx: PluginContext): Promise<void> {
    const vaultDir = typeof ctx.config?.vaultDir === "string" ? ctx.config.vaultDir : undefined;
    const defaultNav = ctx.config?.defaultNavigate !== false;
    const includeStorage = ctx.config?.includeStorage !== false;

    ctx.mcp.registerTool(
      defineTool({
        name: "plugin_auth_capture",
        description:
          "Snapshot active session cookies and origin storage from current tab or URL, encrypt with AES-256-GCM, and save to local vault. Zero credentials leak to LLM context.",
        requiresSession: true,
        schema: {
          service: z.string().optional().describe("Service identifier (e.g. 'github', 'stripe'). Inferred from domain if omitted."),
          url: z.string().optional().describe("Explicit target URL. Inferred from active tab if omitted."),
          include_storage: z.boolean().optional().describe("Whether to capture localStorage along with cookies (default true)."),
        },
        handler: async (args, session) => {
          const res = await captureSession(session, {
            service: args.service,
            url: args.url,
            includeStorage: args.include_storage ?? includeStorage,
            vaultDir,
          });
          return {
            content: [{ type: "text", text: JSON.stringify(res, null, 2) }],
          };
        },
      })
    );

    ctx.mcp.registerTool(
      defineTool({
        name: "plugin_auth_inject",
        description:
          "Decrypt stored session profile and inject cookies + storage directly over CDP. Authenticates page without agent ever seeing credentials.",
        requiresSession: true,
        schema: {
          service: z.string().describe("Target service or domain to inject from vault (e.g. 'github')."),
          url: z.string().optional().describe("Destination URL to navigate after injection."),
          navigate: z.boolean().optional().describe("Whether to navigate to service URL after injection (default true)."),
        },
        handler: async (args, session) => {
          const res = await injectSession(session, {
            service: args.service,
            url: args.url,
            navigate: args.navigate ?? defaultNav,
            vaultDir,
          });
          return {
            content: [{ type: "text", text: JSON.stringify(res, null, 2) }],
          };
        },
      })
    );

    ctx.mcp.registerTool(
      defineTool({
        name: "plugin_auth_list",
        description: "List all encrypted session profiles stored in local vault with safe metadata. No secrets exposed.",
        requiresSession: false,
        schema: {},
        handler: async () => {
          const profiles = await listProfiles(vaultDir);
          return {
            content: [{ type: "text", text: JSON.stringify({ success: true, count: profiles.length, profiles }, null, 2) }],
          };
        },
      })
    );

    ctx.mcp.registerTool(
      defineTool({
        name: "plugin_auth_delete",
        description: "Permanently delete an encrypted session profile from local vault.",
        requiresSession: false,
        schema: {
          service: z.string().describe("Service identifier to delete."),
        },
        handler: async (args) => {
          const ok = await deleteProfile(args.service, vaultDir);
          return {
            content: [{ type: "text", text: JSON.stringify({ success: true, service: args.service, deleted: ok }, null, 2) }],
          };
        },
      })
    );

    ctx.logger?.info("@weavetab/plugin-auth initialized: session vault active");
  },

  async onUnload(ctx: PluginContext): Promise<void> {
    ctx.logger?.info("@weavetab/plugin-auth unloaded");
  },
});

export default authPlugin;
export const plugin = authPlugin;
