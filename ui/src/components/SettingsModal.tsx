import { useState, useEffect } from "react";
import * as api from "../api";
import type { IdentityInfo, StatusInfo, DeviceInfo } from "../api";

interface Props {
  identity: IdentityInfo;
  status: StatusInfo | null;
  onClose: () => void;
}

export default function SettingsModal({ identity, status, onClose }: Props) {
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    api.listDevices().then(setDevices).catch(console.error);
  }, []);

  const handleUploadPrekeys = async () => {
    setUploading(true);
    try {
      const count = await api.uploadPrekeys();
      setMessage(`Uploaded ${count} pre-keys`);
    } catch (err: unknown) {
      setMessage(`Error: ${String(err)}`);
    } finally {
      setUploading(false);
    }
  };

  const handleRevoke = async (deviceId: string) => {
    try {
      await api.revokeDevice(deviceId);
      setDevices((prev) =>
        prev.map((d) =>
          d.device_id === deviceId ? { ...d, active: false } : d,
        ),
      );
    } catch (err: unknown) {
      setMessage(`Error: ${String(err)}`);
    }
  };

  const handleDisconnect = async () => {
    try {
      await api.disconnect();
      setMessage("Disconnected");
    } catch (err: unknown) {
      setMessage(`Error: ${String(err)}`);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Settings</h2>
          <button className="icon-btn" onClick={onClose}>
            ✕
          </button>
        </div>

        {/* Identity info */}
        <section className="settings-section">
          <h3>Identity</h3>
          <div className="info-row">
            <span className="info-label">User ID</span>
            <code className="info-value">{identity.user_id}</code>
          </div>
          <div className="info-row">
            <span className="info-label">Device ID</span>
            <code className="info-value">{identity.device_id}</code>
          </div>
          <div className="info-row">
            <span className="info-label">Created</span>
            <span className="info-value">
              {new Date(identity.created_at).toLocaleDateString()}
            </span>
          </div>
        </section>

        {/* Connection */}
        <section className="settings-section">
          <h3>Connection</h3>
          <div className="info-row">
            <span className="info-label">Status</span>
            <span className="info-value">
              {status?.connection ?? "Unknown"}
            </span>
          </div>
          <div className="info-row">
            <span className="info-label">Relay</span>
            <span className="info-value">{status?.relay_url ?? "—"}</span>
          </div>
          <div className="settings-actions">
            <button className="btn-small" onClick={handleDisconnect}>
              Disconnect
            </button>
            <button
              className="btn-small btn-primary"
              onClick={handleUploadPrekeys}
              disabled={uploading}
            >
              {uploading ? "Uploading…" : "Upload Pre-Keys"}
            </button>
          </div>
        </section>

        {/* Devices */}
        <section className="settings-section">
          <h3>Devices</h3>
          {devices.length === 0 && <p className="muted">No devices found</p>}
          <ul className="device-list">
            {devices.map((d) => (
              <li key={d.device_id} className="device-item">
                <div>
                  <strong>
                    {d.is_current ? "This device" : "Linked device"}
                  </strong>
                  <br />
                  <code>{d.device_id.substring(0, 16)}…</code>
                  {!d.active && <span className="badge-revoked">Revoked</span>}
                </div>
                {d.active && !d.is_current && (
                  <button
                    className="btn-small btn-danger"
                    onClick={() => handleRevoke(d.device_id)}
                  >
                    Revoke
                  </button>
                )}
              </li>
            ))}
          </ul>
        </section>

        {message && <div className="settings-message">{message}</div>}
      </div>
    </div>
  );
}
