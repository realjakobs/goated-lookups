import React from 'react';

export default function AdminQueue({ requests, onClaim, onResolve }) {
  return (
    <div style={{ width: 280, borderRight: '1px solid #ccc', overflowY: 'auto' }}>
      <div style={{ padding: '8px 12px', fontWeight: 600, borderBottom: '1px solid #eee' }}>
        MARx Queue ({requests.length})
      </div>
      {requests.length === 0 && (
        <div style={{ padding: 12, color: '#888', fontSize: 13 }}>Queue is empty</div>
      )}
      {requests.map(req => (
        <div
          key={req.id}
          style={{ padding: '10px 12px', borderBottom: '1px solid #f0f0f0' }}
        >
          <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
            Request {req.id.slice(-8)}
          </div>
          <div style={{ fontSize: 11, color: '#888', marginBottom: 8 }}>
            Agent: {req.agent?.email}<br />
            {new Date(req.createdAt).toLocaleString()}
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            {req.status === 'PENDING' && (
              <button
                onClick={() => onClaim(req.id)}
                style={{ fontSize: 12, padding: '4px 10px', background: '#1a73e8', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
              >
                Claim
              </button>
            )}
            {req.status === 'CLAIMED' && (
              <button
                onClick={() => onResolve(req.id)}
                style={{ fontSize: 12, padding: '4px 10px', background: '#34a853', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
              >
                Resolve
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
