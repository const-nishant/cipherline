import { useState } from "react";
import type { ContactInfo, StatusInfo } from "../api";

interface Props {
  contacts: ContactInfo[];
  selectedContact: string | null;
  onSelectContact: (userId: string) => void;
  onAddContact: (userId: string, displayName: string) => void;
  onOpenSettings: () => void;
  status: StatusInfo | null;
  onConnect: () => void;
}

export default function Sidebar({
  contacts,
  selectedContact,
  onSelectContact,
  onAddContact,
  onOpenSettings,
  status,
  onConnect,
}: Props) {
  const [showAdd, setShowAdd] = useState(false);
  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");

  const handleAdd = () => {
    if (!newId.trim() || !newName.trim()) return;
    onAddContact(newId.trim(), newName.trim());
    setNewId("");
    setNewName("");
    setShowAdd(false);
  };

  const connectionClass =
    status?.connection === "Connected"
      ? "status-connected"
      : "status-disconnected";

  return (
    <aside className="sidebar">
      {/* Header */}
      <div className="sidebar-header">
        <h2>CipherLine</h2>
        <div className="sidebar-actions">
          <button
            className="icon-btn"
            onClick={() => setShowAdd(!showAdd)}
            title="Add contact"
          >
            +
          </button>
          <button
            className="icon-btn"
            onClick={onOpenSettings}
            title="Settings"
          >
            ⚙
          </button>
        </div>
      </div>

      {/* Connection status */}
      <div className={`connection-bar ${connectionClass}`}>
        <span className="status-dot" />
        <span>{status?.connection ?? "Unknown"}</span>
        {status?.connection !== "Connected" && (
          <button className="btn-small" onClick={onConnect}>
            Connect
          </button>
        )}
      </div>

      {/* Add contact form */}
      {showAdd && (
        <div className="add-contact-form">
          <input
            type="text"
            placeholder="User ID (hex)"
            value={newId}
            onChange={(e) => setNewId(e.target.value)}
          />
          <input
            type="text"
            placeholder="Display name"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAdd()}
          />
          <button className="btn-small btn-primary" onClick={handleAdd}>
            Add
          </button>
        </div>
      )}

      {/* Contact list */}
      <ul className="contact-list">
        {contacts.length === 0 && (
          <li className="no-contacts">No contacts yet</li>
        )}
        {contacts.map((c) => (
          <li
            key={c.user_id}
            className={`contact-item ${
              selectedContact === c.user_id ? "selected" : ""
            }`}
            onClick={() => onSelectContact(c.user_id)}
          >
            <div className="contact-avatar">
              {c.display_name.charAt(0).toUpperCase()}
            </div>
            <div className="contact-info">
              <span className="contact-name">{c.display_name}</span>
              <span className="contact-id">{c.user_id.substring(0, 12)}…</span>
            </div>
          </li>
        ))}
      </ul>
    </aside>
  );
}
