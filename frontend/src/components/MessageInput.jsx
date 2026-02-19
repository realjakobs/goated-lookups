import React, { useState } from 'react';

export default function MessageInput({ onSend }) {
  const [value, setValue] = useState('');

  function handleSubmit(e) {
    e.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) return;
    onSend(trimmed);
    setValue('');
  }

  return (
    <form
      onSubmit={handleSubmit}
      style={{ display: 'flex', padding: 12, borderTop: '1px solid #ccc', gap: 8 }}
    >
      <input
        type="text"
        value={value}
        onChange={e => setValue(e.target.value)}
        placeholder="Type a message…"
        style={{ flex: 1, padding: '8px 12px', borderRadius: 20, border: '1px solid #ccc', fontSize: 14 }}
      />
      <button
        type="submit"
        disabled={!value.trim()}
        style={{ padding: '8px 16px', borderRadius: 20, background: '#1a73e8', color: '#fff', border: 'none', cursor: 'pointer' }}
      >
        Send
      </button>
    </form>
  );
}
