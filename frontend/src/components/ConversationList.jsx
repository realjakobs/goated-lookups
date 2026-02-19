import React from 'react';

export default function ConversationList({ conversations, activeId, onSelect }) {
  return (
    <div style={{ width: 240, borderRight: '1px solid #ccc', overflowY: 'auto' }}>
      <div style={{ padding: '8px 12px', fontWeight: 600, borderBottom: '1px solid #eee' }}>
        Conversations
      </div>
      {conversations.length === 0 && (
        <div style={{ padding: 12, color: '#888', fontSize: 13 }}>No conversations yet</div>
      )}
      {conversations.map(conv => (
        <button
          key={conv.id}
          onClick={() => onSelect(conv.id)}
          style={{
            display: 'block',
            width: '100%',
            padding: '10px 12px',
            textAlign: 'left',
            background: conv.id === activeId ? '#e8f0fe' : 'transparent',
            border: 'none',
            borderBottom: '1px solid #f0f0f0',
            cursor: 'pointer',
            fontSize: 13,
          }}
        >
          <div style={{ fontWeight: 500 }}>Request {conv.marxRequest?.id?.slice(-6) ?? conv.id.slice(-6)}</div>
          <div style={{ color: '#888', fontSize: 11 }}>{conv.marxRequest?.status ?? 'OPEN'}</div>
        </button>
      ))}
    </div>
  );
}
