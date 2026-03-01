/**
 * Tauri IPC bridge – typed wrappers around `invoke()`.
 *
 * Types here must exactly mirror the Rust `#[derive(Serialize)]` structs
 * defined in `src-tauri/src/commands.rs`.
 */
import { invoke } from "@tauri-apps/api/core";

// ---------------------------------------------------------------------------
// Types matching the Rust command responses
// ---------------------------------------------------------------------------

export interface IdentityInfo {
  user_id: string;
  device_id: string;
  signing_key: string;
  exchange_key: string;
  created_at: number;
  has_identity: boolean;
}

export interface ContactInfo {
  user_id: string;
  display_name: string;
  added_at: number;
}

export interface MessageInfo {
  id: string;
  conversation_id: string;
  /** The message text (named `content` in Rust). */
  content: string;
  timestamp: number;
  is_outgoing: boolean;
  read: boolean;
}

export interface DeviceInfo {
  device_id: string;
  is_current: boolean;
  active: boolean;
  created_at: number;
}

export interface StatusInfo {
  connection: string;
  has_identity: boolean;
  prekey_count: number;
  relay_url: string;
}

// ---------------------------------------------------------------------------
// IPC wrappers
// ---------------------------------------------------------------------------

export async function createIdentity(
  displayName: string,
): Promise<IdentityInfo> {
  return invoke<IdentityInfo>("create_identity", { displayName });
}

/**
 * Always returns an IdentityInfo object.  When no identity exists the
 * `has_identity` field is `false` and all other fields are empty/zero.
 */
export async function getIdentity(): Promise<IdentityInfo> {
  return invoke<IdentityInfo>("get_identity");
}

export async function connectRelay(): Promise<void> {
  return invoke<void>("connect_relay");
}

export async function getStatus(): Promise<StatusInfo> {
  return invoke<StatusInfo>("get_status");
}

export async function addContact(
  userId: string,
  displayName: string,
): Promise<ContactInfo> {
  return invoke<ContactInfo>("add_contact", {
    userIdHex: userId,
    displayName,
  });
}

export async function getContacts(): Promise<ContactInfo[]> {
  return invoke<ContactInfo[]>("get_contacts");
}

export async function sendMessage(
  contactUserId: string,
  text: string,
): Promise<MessageInfo> {
  return invoke<MessageInfo>("send_message", {
    contactId: contactUserId,
    text,
  });
}

export async function getMessages(
  conversationId: string,
  limit?: number,
  offset?: number,
): Promise<MessageInfo[]> {
  return invoke<MessageInfo[]>("get_messages", {
    conversationId,
    limit: limit ?? 100,
    offset: offset ?? 0,
  });
}

export async function markRead(conversationId: string): Promise<void> {
  return invoke<void>("mark_read", { conversationId });
}

export async function listDevices(): Promise<DeviceInfo[]> {
  return invoke<DeviceInfo[]>("list_devices");
}

export async function revokeDevice(deviceId: string): Promise<void> {
  return invoke<void>("revoke_device", { deviceIdHex: deviceId });
}

export async function uploadPrekeys(): Promise<number> {
  return invoke<number>("upload_prekeys");
}

/** Returns array of `[conversationId, count]` tuples. */
export async function unreadCounts(): Promise<[string, number][]> {
  return invoke<[string, number][]>("unread_counts");
}

export async function fetchPrekeys(userId: string): Promise<void> {
  return invoke<void>("fetch_prekeys", { userIdHex: userId });
}

export async function disconnect(): Promise<void> {
  return invoke<void>("disconnect");
}
