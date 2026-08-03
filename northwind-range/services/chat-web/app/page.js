'use client';

import { useEffect, useState } from 'react';

export default function ChatPage() {
  const [checking, setChecking] = useState(true);
  const [user, setUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);

  useEffect(() => {
    fetch('/api/auth/me')
      .then((res) => {
        if (!res.ok) {
          window.location.href = '/login';
          return null;
        }
        return res.json();
      })
      .then((data) => {
        if (data) setUser(data);
      })
      .finally(() => setChecking(false));
  }, []);

  async function sendMessage(e) {
    e.preventDefault();
    if (!input.trim()) return;
    const question = input;
    setInput('');
    setMessages((m) => [...m, { role: 'user', text: question }]);
    setSending(true);
    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: question }),
      });
      const data = await res.json();
      setMessages((m) => [
        ...m,
        { role: 'assistant', text: res.ok ? data.response : 'Something went wrong.' },
      ]);
    } catch (err) {
      setMessages((m) => [...m, { role: 'assistant', text: 'Could not reach the server.' }]);
    } finally {
      setSending(false);
    }
  }

  if (checking) return null;

  return (
    <main style={{ maxWidth: 640, margin: '0 auto', padding: 16 }}>
      <h1 style={{ fontSize: 20 }}>
        Northwind Assistant {user && <span style={{ fontWeight: 400, fontSize: 14 }}>({user.username})</span>}
      </h1>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
        {messages.map((m, i) => (
          <div key={i}>
            <strong>{m.role === 'user' ? 'You' : 'Assistant'}:</strong>
            <div style={{ whiteSpace: 'pre-wrap' }}>{m.text}</div>
          </div>
        ))}
        {sending && <div>Thinking…</div>}
      </div>
      <form onSubmit={sendMessage} style={{ display: 'flex', gap: 8 }}>
        <input
          style={{ flex: 1 }}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask something…"
        />
        <button type="submit" disabled={sending}>
          Send
        </button>
      </form>
    </main>
  );
}
