/**
 * Push notification helpers for CipherLine.
 *
 * Uses `@tauri-apps/plugin-notification` which maps to:
 * - **Desktop**: OS-native notifications (Windows toast, macOS Notification Center)
 * - **Android**: Android notification channels via FCM-compatible API
 * - **iOS**: APNs via iOS Notification Center
 */
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";

let permissionGranted = false;

/**
 * Request notification permission if not already granted.
 * Call this early in app lifecycle (e.g., after identity creation).
 */
export async function ensureNotificationPermission(): Promise<boolean> {
  try {
    permissionGranted = await isPermissionGranted();
    if (!permissionGranted) {
      const result = await requestPermission();
      permissionGranted = result === "granted";
    }
  } catch {
    // Plugin may not be available on all platforms
    permissionGranted = false;
  }
  return permissionGranted;
}

/**
 * Show a notification for an incoming message.
 */
export async function notifyIncomingMessage(
  senderName: string,
  messagePreview: string,
): Promise<void> {
  if (!permissionGranted) {
    await ensureNotificationPermission();
  }
  if (!permissionGranted) return;

  try {
    sendNotification({
      title: `New message from ${senderName}`,
      body:
        messagePreview.length > 100
          ? messagePreview.slice(0, 97) + "..."
          : messagePreview,
    });
  } catch {
    // Swallow notification errors — non-critical
  }
}

/**
 * Show a generic notification.
 */
export async function notify(
  title: string,
  body: string,
): Promise<void> {
  if (!permissionGranted) {
    await ensureNotificationPermission();
  }
  if (!permissionGranted) return;

  try {
    sendNotification({ title, body });
  } catch {
    // Swallow notification errors — non-critical
  }
}
