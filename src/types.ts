export interface VaultCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "Strict" | "Lax" | "None";
}

export interface VaultProfile {
  version: 1;
  service: string;
  domain: string;
  origin: string;
  capturedAt: string;
  cookies: VaultCookie[];
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
}

export interface ProfileMeta {
  service: string;
  domain: string;
  origin: string;
  capturedAt: string;
  cookieCount: number;
  storageKeyCount: number;
  file: string;
}

export interface CaptureOptions {
  service?: string;
  url?: string;
  includeStorage?: boolean;
  vaultDir?: string;
}

export interface InjectOptions {
  service: string;
  url?: string;
  navigate?: boolean;
  vaultDir?: string;
}
