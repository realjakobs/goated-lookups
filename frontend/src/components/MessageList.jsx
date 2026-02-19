import React, { useEffect, useRef } from 'react';

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
                  {msg.sender?.email}
                </div>
              )}
              <div className="leading-relaxed">{msg.content}</div>
              <div className={`text-xs mt-1 text-right ${isMine ? 'text-blue-200' : 'text-gray-500'}`}>
                {new Date(msg.createdAt).toLocaleTimeString()}
              </div>
            </div>
          </div>
        );
      })}
      <div ref={bottomRef} />
    </div>
  );
}
