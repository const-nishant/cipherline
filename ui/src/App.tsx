import { useState, useEffect } from "react";
import * as api from "./api";
import type { IdentityInfo, ContactInfo, MessageInfo, StatusInfo } from "./api";
import { listen } from "@tauri-apps/api/event";
import {
  ensureNotificationPermission,
  notifyIncomingMessage,
} from "./notifications";

import SetupScreen from "./components/SetupScreen";
import Sidebar from "./components/Sidebar";
import ChatView from "./components/ChatView";
import SettingsModal from "./components/SettingsModal";

export default function App() {
  const [identity, setIdentity] = useState<IdentityInfo | null>(null);
  const [contacts, setContacts] = useState<ContactInfo[]>([]);
  const [selectedContact, setSelectedContact] = useState<string | null>(null);
  const [messages, setMessages] = useState<MessageInfo[]>([]);
  const [status, setStatus] = useState<StatusInfo | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [loading, setLoading] = useState(true);

  // ------ bootstrap ------
  useEffect(() => {
    (async () => {
      try {
        const id = await api.getIdentity();
        if (id.has_identity) {
          setIdentity(id);
          const c = await api.getContacts();
          setContacts(c);
          // Auto-connect to relay on startup
          try {
            await api.connectRelay();
          } catch {
            // May already be connected or relay unavailable
          }
          const s = await api.getStatus();
          setStatus(s);
        }
      } catch (err) {
        console.error("init error", err);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  // ------ listen for connection-status events ------
  useEffect(() => {
    const unlisten = listen<string>("connection-status", (event) => {
      setStatus((prev) =>
        prev
          ? { ...prev, connection: event.payload }
          : {
              connection: event.payload,
              has_identity: true,
              prekey_count: 0,
              relay_url: "",
            },
      );
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  // ------ listen for new-message events ------
  useEffect(() => {
    const unlisten = listen<MessageInfo>("new-message", (event) => {
      const msg = event.payload;
      setMessages((prev) => {
        if (msg.conversation_id === selectedContact) {
          return [...prev, msg];
        }
        return prev;
      });
      // Show push notification if message is from another user
      if (!msg.is_outgoing) {
        const sender = contacts.find((c) => c.user_id === msg.conversation_id);
        notifyIncomingMessage(sender?.display_name ?? "Unknown", msg.content);
      }
      // Refresh contacts to update unread counts
      api.getContacts().then(setContacts).catch(console.error);
    });

    return () => {
      unlisten.then((fn) => fn());
    };
  }, [selectedContact]);

  // ------ listen for session-established events ------
  useEffect(() => {
    const unlisten = listen<{ user_id: string; device_id: string }>(
      "session-established",
      (event) => {
        console.log("Session established with", event.payload.user_id);
        // Refresh status to update prekey count
        api.getStatus().then(setStatus).catch(console.error);
      },
    );
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  // ------ load messages when contact changes ------
  useEffect(() => {
    if (!selectedContact) {
      setMessages([]);
      return;
    }
    api.getMessages(selectedContact).then(setMessages).catch(console.error);
  }, [selectedContact]);

  // ------ identity created callback ------
  const handleIdentityCreated = async (id: IdentityInfo) => {
    setIdentity(id);
    // Request notification permission after identity setup
    await ensureNotificationPermission();
    try {
      await api.connectRelay();
      const s = await api.getStatus();
      setStatus(s);
    } catch (err) {
      console.error("connect error", err);
    }
  };

  // ------ send message ------
  const handleSend = async (text: string) => {
    if (!selectedContact) return;
    try {
      const msg = await api.sendMessage(selectedContact, text);
      setMessages((prev) => [...prev, msg]);
    } catch (err) {
      console.error("send error", err);
    }
  };

  // ------ add contact ------
  const handleAddContact = async (userId: string, displayName: string) => {
    try {
      const contact = await api.addContact(userId, displayName);
      setContacts((prev) => [...prev, contact]);
    } catch (err) {
      console.error("add contact error", err);
    }
  };

  // ------ connect ------
  const handleConnect = async () => {
    try {
      await api.connectRelay();
      const s = await api.getStatus();
      setStatus(s);
    } catch (err) {
      console.error("connect error", err);
    }
  };

  if (loading) {
    return <div className="loading">Loading…</div>;
  }

  if (!identity) {
    return <SetupScreen onCreated={handleIdentityCreated} />;
  }

  return (
    <div className="app">
      <Sidebar
        contacts={contacts}
        selectedContact={selectedContact}
        onSelectContact={(id) => {
          setSelectedContact(id);
          api.markRead(id).catch(console.error);
        }}
        onAddContact={handleAddContact}
        onOpenSettings={() => setShowSettings(true)}
        status={status}
        onConnect={handleConnect}
      />
      <main className="main">
        {selectedContact ? (
          <ChatView
            conversationId={selectedContact}
            messages={messages}
            onSend={handleSend}
            myUserId={identity.user_id}
          />
        ) : (
          <div className="empty-state">
            <h2>CipherLine</h2>
            <p>Select a contact to start messaging</p>
          </div>
        )}
      </main>
      {showSettings && (
        <SettingsModal
          identity={identity}
          status={status}
          onClose={() => setShowSettings(false)}
        />
      )}
    </div>
  );
}
