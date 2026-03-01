import { useState } from "react";
import * as api from "../api";
import type { IdentityInfo } from "../api";

interface Props {
  onCreated: (identity: IdentityInfo) => void;
}

export default function SetupScreen({ onCreated }: Props) {
  const [displayName, setDisplayName] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreate = async () => {
    if (!displayName.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const identity = await api.createIdentity(displayName.trim());
      onCreated(identity);
    } catch (err: unknown) {
      setError(String(err));
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="setup-screen">
      <div className="setup-card">
        <div className="setup-logo">🔐</div>
        <h1>Welcome to CipherLine</h1>
        <p className="setup-subtitle">
          End-to-end encrypted messaging. Create your identity to get started.
        </p>

        <div className="setup-form">
          <label htmlFor="displayName">Display Name</label>
          <input
            id="displayName"
            type="text"
            placeholder="Enter your name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleCreate()}
            disabled={creating}
            autoFocus
          />

          <button
            className="btn-primary"
            onClick={handleCreate}
            disabled={creating || !displayName.trim()}
          >
            {creating ? "Creating Identity…" : "Create Identity"}
          </button>

          {error && <div className="error-message">{error}</div>}
        </div>

        <p className="setup-footer">
          Your cryptographic keys are generated locally and never leave your
          device.
        </p>
      </div>
    </div>
  );
}
