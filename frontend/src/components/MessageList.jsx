import React, { useEffect, useRef } from 'react';

function getSenderLabel(sender) {
  if (sender?.role === 'ADMIN') return 'Admin';
  // Show the part of the email before @ as the agent's display name
  return sender?.email?.split('@')[0] ?? 'Agent';
}

export default function MessageList({ messages, currentUserId }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  return (
    <div className="flex-1 overflow-y-auto px-4 py-4 space-y-3 bg-gray-900">
      {messages.map(msg => {
        const isMine = msg.sender?.id === currentUserId;
        return (
          <div
            key={msg.id}
            className={`flex ${isMine ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[70%] px-4 py-2.5 rounded-2xl text-sm shadow-sm
                ${isMine
                  ? 'bg-blue-600 text-white rounded-br-sm'
                  : 'bg-gray-700 text-gray-100 rounded-bl-sm'
                }`}
            >
              {!isMine && (
                <div className="text-xs font-semibold text-blue-400 mb-1">
                  {getSenderLabel(msg.sender)}
                </div>
              )}

              {msg.imageDataUrl && (
                <img
                  src={msg.imageDataUrl}
                  alt="Shared image"
                  className="max-w-[260px] w-full rounded-lg cursor-pointer mb-1"
                  onClick={() => window.open(msg.imageDataUrl)}
                  title="Click to open full size"
                />
              )}

              {msg.content && (
                <div className="leading-relaxed">{msg.content}</div>
              )}
            </div>
          </div>
        );
      })}
      <div ref={bottomRef} />
    </div>
  );
}
