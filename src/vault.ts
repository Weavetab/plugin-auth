import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as crypto from "node:crypto";
import type { VaultProfile, ProfileMeta } from "./types.js";

const DEFAULT_VAULT_DIR = path.join(os.homedir(), ".weavetab", "vault");

export function resolveVaultDir(custom?: string): string {
  const dir = custom && custom.trim() ? custom.trim() : DEFAULT_VAULT_DIR;
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

export function sanitizeService(name: string): string {
  return name.trim().toLowerCase().replace(/https?:\/\//, "").replace(/[^a-z0-9._-]/g, "_");
}

let cachedKey: Buffer | null = null;

export function getMasterKey(vaultDir: string): Buffer {
  if (cachedKey) return cachedKey;

  const keyPath = path.join(vaultDir, ".master.key");
  try {
    if (fs.existsSync(keyPath)) {
      const raw = fs.readFileSync(keyPath, "utf-8").trim();
      cachedKey = Buffer.from(raw, "hex");
      return cachedKey;
    }

    const generated = crypto.randomBytes(32);
    fs.writeFileSync(keyPath, generated.toString("hex"), { mode: 0o600 });
    cachedKey = generated;
    return cachedKey;
  } catch {
    // fallback when filesystem permissions block key file creation
    const seed = `${os.hostname()}:${os.platform()}:${os.userInfo().username}`;
    cachedKey = crypto.createHash("sha256").update(seed).digest();
    return cachedKey;
  }
}

export function encryptPayload(data: string, vaultDir: string): string {
  const key = getMasterKey(vaultDir);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let enc = cipher.update(data, "utf8", "hex");
  enc += cipher.final("hex");
  const tag = cipher.getAuthTag();

  return iv.toString("hex") + tag.toString("hex") + enc;
}

export function decryptPayload(blob: string, vaultDir: string): string {
  const key = getMasterKey(vaultDir);
  const iv = Buffer.from(blob.slice(0, 32), "hex");
  const tag = Buffer.from(blob.slice(32, 64), "hex");
  const enc = blob.slice(64);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  let dec = decipher.update(enc, "hex", "utf8");
  dec += decipher.final("utf8");
  return dec;
}

export async function saveProfile(profile: VaultProfile, customDir?: string): Promise<{ file: string; path: string }> {
  const dir = resolveVaultDir(customDir);
  const slug = sanitizeService(profile.service || profile.domain);
  const fileName = `${slug}.enc`;
  const filePath = path.join(dir, fileName);

  const json = JSON.stringify(profile);
  const encrypted = encryptPayload(json, dir);

  fs.writeFileSync(filePath, encrypted, { mode: 0o600 });
  return { file: fileName, path: filePath };
}

export async function loadProfile(service: string, customDir?: string): Promise<VaultProfile | null> {
  const dir = resolveVaultDir(customDir);
  const slug = sanitizeService(service);
  const filePath = path.join(dir, `${slug}.enc`);

  if (!fs.existsSync(filePath)) return null;

  try {
    const raw = fs.readFileSync(filePath, "utf-8").trim();
    const dec = decryptPayload(raw, dir);
    return JSON.parse(dec) as VaultProfile;
  } catch {
    return null;
  }
}

export async function listProfiles(customDir?: string): Promise<ProfileMeta[]> {
  const dir = resolveVaultDir(customDir);
  if (!fs.existsSync(dir)) return [];

  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".enc"));
  const profiles: ProfileMeta[] = [];

  for (const file of files) {
    try {
      const full = path.join(dir, file);
      const raw = fs.readFileSync(full, "utf-8").trim();
      const dec = decryptPayload(raw, dir);
      const prof = JSON.parse(dec) as VaultProfile;

      profiles.push({
        service: prof.service,
        domain: prof.domain,
        origin: prof.origin,
        capturedAt: prof.capturedAt,
        cookieCount: prof.cookies?.length || 0,
        storageKeyCount: Object.keys(prof.localStorage || {}).length,
        file,
      });
    } catch {
      // corrupt or foreign key file, skip
    }
  }

  return profiles;
}

export async function deleteProfile(service: string, customDir?: string): Promise<boolean> {
  const dir = resolveVaultDir(customDir);
  const slug = sanitizeService(service);
  const filePath = path.join(dir, `${slug}.enc`);

  if (!fs.existsSync(filePath)) return false;

  fs.unlinkSync(filePath);
  return true;
}
