import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../lib/api.js';
import AdminQueue from '../components/AdminQueue.jsx';
import ConversationList from '../components/ConversationList.jsx';
import MessageList from '../components/MessageList.jsx';
import MessageInput from '../components/MessageInput.jsx';

export default function AdminPage() {
  const { user, token, logout } = useAuth();
  const [queue, setQueue] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [activeConvId, setActiveConvId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);

  // Connect socket
  useEffect(() => {
    const s = io(import.meta.env.VITE_API_URL || '', { auth: { token } });
    setSocket(s);

    s.on('new-marx-request', (req) => {
      setQueue(prev => [req, ...prev]);
    });

    s.on('request-claimed', ({ requestId }) => {
      setQueue(prev => prev.filter(r => r.id !== requestId));
    });

    return () => s.disconnect();
  }, [token]);

  // Load initial queue and conversations
  useEffect(() => {
    api.get('/admin/queue').then(r => setQueue(r.data));
    api.get('/conversations').then(r => setConversations(r.data));
  }, []);

  // Load messages for active conversation
  useEffect(() => {
    if (!activeConvId) { setMessages([]); return; }
    api.get(`/messages/${activeConvId}`).then(r => setMessages(r.data));
    socket?.emit('join-conversation', activeConvId);
    return () => socket?.emit('leave-conversation', activeConvId);
  }, [activeConvId, socket]);

  useEffect(() => {
    if (!socket) return;
    const handler = (msg) => {
      if (msg.conversationId === activeConvId) {
        setMessages(prev => [...prev, msg]);
      }
    };
    socket.on('new-message', handler);
    return () => socket.off('new-message', handler);
  }, [socket, activeConvId]);

  async function claimRequest(requestId) {
    const { data } = await api.post(`/admin/claim/${requestId}`);
    setQueue(prev => prev.filter(r => r.id !== requestId));
    const convRes = await api.get('/conversations');
    setConversations(convRes.data);
    setActiveConvId(data.conversation.id);
  }

  async function resolveRequest(requestId) {
    await api.post(`/admin/resolve/${requestId}`);
    const convRes = await api.get('/conversations');
    setConversations(convRes.data);
  }

  async function sendMessage(content) {
    const { data } = await api.post(`/messages/${activeConvId}`, { content });
    setMessages(prev => [...prev, data]);
  }

  const [inviteUrl, setInviteUrl] = useState('');
  async function createInvite() {
    const { data } = await api.post('/admin/invites');
    setInviteUrl(data.inviteUrl);
  }

  const [showUsers, setShowUsers] = useState(false);
  const [agentUsers, setAgentUsers] = useState([]);

  async function openUsers() {
    const { data } = await api.get('/admin/users');
    setAgentUsers(data);
    setShowUsers(true);
  }

  async function deactivateUser(id) {
    await api.post(`/admin/users/${id}/deactivate`);
    setAgentUsers(prev => prev.map(u => u.id === id ? { ...u, isActive: false } : u));
  }

  async function activateUser(id) {
    await api.post(`/admin/users/${id}/activate`);
    setAgentUsers(prev => prev.map(u =>
      u.id === id ? { ...u, isActive: true, lockedUntil: null, failedLoginAttempts: 0 } : u,
    ));
  }

  return (
    <div style={{ display: 'flex', height: '100vh', flexDirection: 'column' }}>
      <header style={{ padding: '8px 16px', borderBottom: '1px solid #ccc', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>Goated Lookups — Admin ({user.email})</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <button onClick={createInvite}>+ Invite Agent</button>
          {inviteUrl && (
            <span style={{ fontSize: 12 }}>
              <input
                readOnly
                value={inviteUrl}
                style={{ width: 320, marginRight: 4 }}
                onFocus={e => e.target.select()}
              />
              <button onClick={() => { navigator.clipboard.writeText(inviteUrl); }}>Copy</button>
              <button onClick={() => setInviteUrl('')} style={{ marginLeft: 4 }}>✕</button>
            </span>
          )}
          <button onClick={openUsers}>Manage Agents</button>
          <button onClick={logout}>Logout</button>
        </div>
      </header>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <AdminQueue
          requests={queue}
          onClaim={claimRequest}
          onResolve={resolveRequest}
        />
        <ConversationList
          conversations={conversations}
          activeId={activeConvId}
          onSelect={setActiveConvId}
        />
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          {activeConvId
            ? <>
                <MessageList messages={messages} currentUserId={user.id} />
                <MessageInput onSend={sendMessage} />
              </>
            : <div style={{ margin: 'auto', color: '#888' }}>Select a conversation or claim a request</div>
          }
        </div>
      </div>

      {/* Agent management modal */}
      {showUsers && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ background: 'white', borderRadius: 8, padding: 24, minWidth: 440, maxHeight: '80vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h2 style={{ margin: 0 }}>Agent Accounts</h2>
              <button onClick={() => setShowUsers(false)}>✕</button>
            </div>
            {agentUsers.length === 0 ? (
              <p style={{ color: '#888' }}>No agents registered yet.</p>
            ) : (
              agentUsers.map(u => {
                const isLocked = u.lockedUntil && new Date(u.lockedUntil) > new Date();
                return (
                  <div key={u.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid #eee' }}>
                    <div>
                      <div style={{ fontWeight: 500 }}>{u.email}</div>
                      <div style={{ fontSize: 12, marginTop: 2, color: !u.isActive ? '#d32f2f' : isLocked ? '#e65100' : '#388e3c' }}>
                        {!u.isActive ? 'Deactivated' : isLocked ? 'Locked (awaiting email unlock)' : 'Active'}
                      </div>
                    </div>
                    <button
                      onClick={() => u.isActive ? deactivateUser(u.id) : activateUser(u.id)}
                      style={{ color: u.isActive ? '#d32f2f' : '#388e3c', minWidth: 90 }}
                    >
                      {u.isActive ? 'Deactivate' : 'Activate'}
                    </button>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
