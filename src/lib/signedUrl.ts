import { supabase } from "./supabase";

// Buckets made private in migration 0084; files are opened through short-lived signed URLs.
export type PrivateBucket = "uploads" | "dispatch-receipts" | "engagement-docs" | "compliance-docs" | "project-docs";

const SIGNED_URL_TTL_SECONDS = 60 * 60;

// Stored values are normally object paths, but older rows may hold a full public URL
// (".../storage/v1/object/public/<bucket>/<path>") — reduce either to the object path.
export function storagePathFor(bucket: PrivateBucket, pathOrUrl: string): string {
  const marker = `/object/public/${bucket}/`;
  const at = pathOrUrl.indexOf(marker);
  const path = at >= 0 ? pathOrUrl.slice(at + marker.length).split("?")[0] : pathOrUrl;
  return decodeURIComponent(path.replace(/^\/+/, ""));
}

/** Signed URL for a private object, or null if the caller may not read it. */
export async function signedUrlFor(bucket: PrivateBucket, pathOrUrl: string, downloadName?: string): Promise<string | null> {
  const { data, error } = await supabase.storage
    .from(bucket)
    .createSignedUrl(storagePathFor(bucket, pathOrUrl), SIGNED_URL_TTL_SECONDS, downloadName ? { download: downloadName } : undefined);
  if (error || !data) return null;
  return data.signedUrl;
}

/**
 * Open (or, with downloadName, download) a private object. The tab is opened synchronously,
 * inside the click, so popup blockers allow it; it is pointed at the URL once signed.
 * Returns false when the URL could not be signed.
 */
export async function openSignedUrl(bucket: PrivateBucket, pathOrUrl: string, downloadName?: string): Promise<boolean> {
  const tab = downloadName ? null : window.open("", "_blank");
  const url = await signedUrlFor(bucket, pathOrUrl, downloadName);
  if (!url) { tab?.close(); return false; }
  if (downloadName) { window.location.assign(url); return true; }
  if (tab) { tab.opener = null; tab.location.href = url; } else window.open(url, "_blank", "noopener");
  return true;
}
