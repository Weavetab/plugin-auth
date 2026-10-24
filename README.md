# `@weavetab/plugin-auth`

> Zero-Leak Enterprise Session & Cookie Vault for [Weavetab](https://weavetab.dev).

Capture, encrypt, and inject authenticated browser sessions directly over the Chrome DevTools Protocol socket without exposing credentials or session tokens to agent prompt context.

---

## The Problem

When AI coding and automation agents encounter OAuth flows, 2FA prompts, or SSO authentication barriers, they break. Passing raw cookies or credentials directly into LLM prompts creates severe security risks, prompt injection vulnerabilities, and token budget exhaustion.

## The Architecture

`@weavetab/plugin-auth` solves authentication via Layer 0 CDP:

1. **Snapshot (`plugin_auth_capture`)**: Extracts active cookies and origin storage from the developer's real browser session. The bundle is immediately encrypted on disk using AES-256-GCM with a local machine key (`~/.weavetab/vault/<service>.enc`).
2. **Zero-Token Injection (`plugin_auth_inject`)**: When the agent operates on that service, it calls `plugin_auth_inject({ service: "github" })`. The plugin decrypts the bundle locally and writes cookies directly into the browser tab via CDP `Network.setCookies`.
3. **Zero Credentials in Prompt Context**: The LLM prompt context receives only execution metadata (`{ success: true, service: "github", authenticated: true }`). Raw tokens never touch agent conversation context.

---

## Tools

### `plugin_auth_capture`
Snapshots active session cookies and origin storage from the active tab or target URL.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | No | Identifier for the profile (e.g. `github`, `stripe`). Inferred from domain if omitted. |
| `url` | string | No | URL to capture cookies for. Inferred from active tab if omitted. |
| `include_storage` | boolean | No | Whether to snapshot localStorage (default `true`). |

### `plugin_auth_inject`
Decrypts and injects cookies and origin storage directly into the active browser tab over CDP.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Identifier of the profile to inject (e.g. `github`). |
| `url` | string | No | Target URL to navigate to after injection. Defaults to captured origin. |
| `navigate` | boolean | No | Whether to navigate after injecting cookies (default `true`). |

### `plugin_auth_list`
Lists all encrypted session profiles stored in the local vault with safe metadata.

### `plugin_auth_delete`
Permanently deletes an encrypted session profile from the local vault.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Identifier of the profile to delete. |

---

## Installation

```bash
weavetab plugin add @weavetab/plugin-auth
```

Or install locally in development:

```bash
cd plugins/plugin-auth
npm install
npm run build
npm test
```

---

## License

MIT © [Weavetab](https://weavetab.dev)
