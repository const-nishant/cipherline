import { useState, useRef, useEffect } from "react";
import type { MessageInfo } from "../api";

interface Props {
  conversationId: string;
  messages: MessageInfo[];
  onSend: (text: string) => void;
  myUserId: string;
}

export default function ChatView({
  conversationId,
  messages,
  onSend,
  myUserId,
}: Props) {
  const [draft, setDraft] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Clear draft when conversation changes
  useEffect(() => {
    setDraft("");
  }, [conversationId]);

  const handleSend = () => {
    const text = draft.trim();
    if (!text) return;
    onSend(text);
    setDraft("");
  };

  const formatTime = (ts: number) => {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  return (
    <div className="chat-view">
      {/* Message list */}
      <div className="message-list">
        {messages.length === 0 && (
          <div className="empty-chat">
            <p>No messages yet. Say hello!</p>
          </div>
        )}
        {messages.map((msg) => {
          const isOutgoing = msg.is_outgoing;
          return (
            <div
              key={msg.id}
              className={`message ${isOutgoing ? "outgoing" : "incoming"}`}
            >
              <div className="bubble">
                <p className="bubble-text">{msg.content}</p>
                <span className="bubble-time">{formatTime(msg.timestamp)}</span>
              </div>
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>

      {/* Compose bar */}
      <div className="compose-bar">
        <input
          type="text"
          className="compose-input"
          placeholder="Type a message…"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              handleSend();
            }
          }}
          autoFocus
        />
        <button
          className="btn-send"
          onClick={handleSend}
          disabled={!draft.trim()}
        >
          Send
        </button>
      </div>
    </div>
  );
}
