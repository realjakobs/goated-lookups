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

  const canSend = value.trim().length > 0;

  return (
    <form
      onSubmit={handleSubmit}
      className="flex items-center gap-3 px-4 py-3 bg-gray-800 border-t border-gray-700 shrink-0"
    >
      <input
        type="text"
        value={value}
        onChange={e => setValue(e.target.value)}
        placeholder="Type a message…"
        className="flex-1 bg-gray-700 border border-gray-600 text-white placeholder-gray-500
                   rounded-full px-4 py-2 text-sm
                   focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                   transition duration-150"
      />
      <button
        type="submit"
        disabled={!canSend}
        className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:text-gray-500 disabled:cursor-not-allowed
                   text-white font-medium px-5 py-2 rounded-full text-sm
                   transition duration-150 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800"
      >
        Send
      </button>
    </form>
  );
}
