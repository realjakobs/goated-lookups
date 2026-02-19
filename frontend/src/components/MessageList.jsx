import React, { useEffect, useRef } from 'react';

export default function MessageList({ messages, currentUserId }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
      {messages.map(msg => {
        const isMine = msg.sender?.id === currentUserId;
        return (
          <div
            key={msg.id}
            style={{
              display: 'flex',
              justifyContent: isMine ? 'flex-end' : 'flex-start',
              marginBottom: 8,
            }}
          >
            <div
              style={{
                maxWidth: '70%',
                padding: '8px 12px',
                borderRadius: 12,
                background: isMine ? '#1a73e8' : '#f1f3f4',
                color: isMine ? '#fff' : '#202124',
                fontSize: 14,
              }}
            >
              {!isMine && (
                <div style={{ fontSize: 11, fontWeight: 600, marginBottom: 4 }}>
                  {msg.sender?.email}
                </div>
              )}
              <div>{msg.content}</div>
              <div style={{ fontSize: 10, opacity: 0.7, marginTop: 4, textAlign: 'right' }}>
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
