import React, { useEffect, useState, useRef } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../lib/api.js';
import AdminQueue from '../components/AdminQueue.jsx';
import ConversationList from '../components/ConversationList.jsx';
import MessageList from '../components/MessageList.jsx';
import MessageInput from '../components/MessageInput.jsx';
import { useMessageSound } from '../hooks/useMessageSound.js';
import BellButton from '../components/BellButton.jsx';

export default function AdminPage() {
  const { user, token, logout } = useAuth();
  const [queue, setQueue] = useState([]);
  const [conversations, setConversations] = useState([]);
  const [activeConvId, setActiveConvId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  const { soundEnabled, toggleSound, notify } = useMessageSound();
  const [dragActive, setDragActive] = useState(false);
  const [droppedFile, setDroppedFile] = useState(null);
  const dragCounterRef = useRef(0);

  useEffect(() => {
    const s = io(import.meta.env.VITE_API_URL || '', { auth: { token } });
    setSocket(s);
    s.on('new-marx-request', (req) => { setQueue(prev => [req, ...prev]); });
    s.on('request-claimed', ({ requestId }) => { setQueue(prev => prev.filter(r => r.id !== requestId)); });
    return () => s.disconnect();
  }, [token]);

  useEffect(() => {
    api.get('/admin/queue').then(r => setQueue(r.data));
    api.get('/conversations').then(r => setConversations(r.data));
  }, []);

  useEffect(() => {
    if (!activeConvId) { setMessages([]); return; }
    api.get(`/messages/${activeConvId}`).then(r => setMessages(r.data));
    socket?.emit('join-conversation', activeConvId);
    return () => socket?.emit('leave-conversation', activeConvId);
  }, [activeConvId, socket]);

  useEffect(() => {
    if (!socket) return;

    const onMessage = (msg) => {
      // Only add messages from others — we already add our own locally on send
      if (msg.conversationId === activeConvId && msg.sender?.id !== user.id) {
        setMessages(prev => [...prev, msg]);
        notify();
      }
    };

    const onExpired = ({ conversationId, messageIds }) => {
      if (conversationId === activeConvId) {
        setMessages(prev => prev.filter(m => !messageIds.includes(m.id)));
      }
    };

    socket.on('new-message', onMessage);
    socket.on('messages-expired', onExpired);
    return () => {
      socket.off('new-message', onMessage);
      socket.off('messages-expired', onExpired);
    };
  }, [socket, activeConvId, user.id, notify]);

  async function claimRequest(requestId) {
    try {
      const { data } = await api.post(`/admin/claim/${requestId}`);
      setQueue(prev => prev.filter(r => r.id !== requestId));
      // Refresh conversation list; navigate to the claimed conv regardless of whether refresh succeeds
      try {
        const convRes = await api.get('/conversations');
        setConversations(convRes.data);
      } catch {
        // Ignore list-refresh failure — we still navigate below
      }
      setActiveConvId(data.conversation.id);
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to claim request. Please try again.');
    }
  }

  async function resolveRequest(requestId) {
    try {
      await api.post(`/admin/resolve/${requestId}`);
      // Navigate away and remove the conversation from the list
      setActiveConvId(null);
      try {
        const convRes = await api.get('/conversations');
        setConversations(convRes.data);
      } catch {
        // Ignore list-refresh failure; remove locally as fallback
        setConversations(prev => prev.filter(c => c.marxRequest?.id !== requestId));
      }
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to resolve request. Please try again.');
    }
  }

  async function sendMessage(content, file) {
    let payload;
    if (file) {
      payload = new FormData();
      payload.append('content', content);
      payload.append('image', file);
    } else {
      payload = { content };
    }
    const { data } = await api.post(`/messages/${activeConvId}`, payload);
    setMessages(prev => [...prev, data]);
  }

  function handleDragEnter(e) {
    e.preventDefault();
    dragCounterRef.current++;
    if (e.dataTransfer.items.length > 0) setDragActive(true);
  }

  function handleDragLeave(e) {
    e.preventDefault();
    dragCounterRef.current--;
    if (dragCounterRef.current === 0) setDragActive(false);
  }

  function handleDrop(e) {
    e.preventDefault();
    dragCounterRef.current = 0;
    setDragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (file && file.type.startsWith('image/')) {
      setDroppedFile(file);
      setTimeout(() => setDroppedFile(null), 100);
    }
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
    <div className="flex h-screen flex-col bg-gray-900">
      <header className="flex items-center justify-between px-5 py-3 bg-gray-800 border-b border-gray-700 shrink-0 gap-4">
        <span className="font-semibold text-white shrink-0">
          Goated Lookups
          <span className="ml-2 text-gray-400 font-normal text-sm">— Admin</span>
          <span className="ml-1 text-gray-500 text-xs">({user.email})</span>
        </span>

        <div className="flex items-center gap-2 flex-wrap justify-end">
          <button
            onClick={createInvite}
            className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium
                       px-4 py-1.5 rounded-lg transition duration-150
                       focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800"
          >
            + Invite Agent
          </button>

          {inviteUrl && (
            <span className="flex items-center gap-2 bg-gray-700 rounded-lg px-3 py-1.5 border border-gray-600">
              <input
                readOnly
                value={inviteUrl}
                className="w-72 bg-transparent text-gray-300 text-xs focus:outline-none"
                onFocus={e => e.target.select()}
              />
              <button
                onClick={() => { navigator.clipboard.writeText(inviteUrl); }}
                className="text-blue-400 hover:text-blue-300 text-xs font-medium transition duration-150"
              >
                Copy
              </button>
              <button
                onClick={() => setInviteUrl('')}
                className="text-gray-500 hover:text-gray-300 transition duration-150 text-xs"
              >
                ✕
              </button>
            </span>
          )}

          <button
            onClick={openUsers}
            className="text-gray-300 hover:text-white text-sm px-3 py-1.5 rounded-lg
                       hover:bg-gray-700 border border-gray-600 transition duration-150"
          >
            Manage Agents
          </button>
          <BellButton enabled={soundEnabled} onToggle={toggleSound} />
          <button
            onClick={logout}
            className="text-gray-400 hover:text-white text-sm px-3 py-1.5 rounded-lg
                       hover:bg-gray-700 transition duration-150"
          >
            Logout
          </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <AdminQueue requests={queue} onClaim={claimRequest} onResolve={resolveRequest} />
        <ConversationList conversations={conversations} activeId={activeConvId} onSelect={setActiveConvId} />
        <div
          className="relative flex flex-1 flex-col overflow-hidden"
          onDragEnter={handleDragEnter}
          onDragLeave={handleDragLeave}
          onDragOver={e => e.preventDefault()}
          onDrop={handleDrop}
        >
          {dragActive && activeConvId && (
            <div className="absolute inset-0 z-10 flex items-center justify-center
                            bg-gray-900/80 border-2 border-dashed border-blue-500 pointer-events-none">
              <div className="text-center">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
                  stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
                  className="w-12 h-12 text-blue-400 mx-auto mb-3">
                  <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                  <circle cx="8.5" cy="8.5" r="1.5" />
                  <polyline points="21 15 16 10 5 21" />
                </svg>
                <p className="text-blue-400 font-semibold text-lg">Drop image to send</p>
              </div>
            </div>
          )}

          {activeConvId ? (
            <>
              {(() => {
                const activeConv = conversations.find(c => c.id === activeConvId);
                return activeConv?.marxRequest?.status === 'CLAIMED' ? (
                  <div className="px-4 py-2 bg-gray-800/80 border-b border-gray-700 shrink-0 flex items-center justify-between">
                    <span className="text-xs text-yellow-400 font-medium">Request claimed — mark resolved when done</span>
                    <button
                      onClick={() => resolveRequest(activeConv.marxRequest.id)}
                      className="bg-green-600 hover:bg-green-700 text-white text-xs font-medium
                                 px-3 py-1 rounded-lg transition duration-150
                                 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 focus:ring-offset-gray-900"
                    >
                      Mark Resolved
                    </button>
                  </div>
                ) : null;
              })()}
              <MessageList messages={messages} currentUserId={user.id} />
              <MessageInput onSend={sendMessage} droppedFile={droppedFile} />
            </>
          ) : (
            <div className="m-auto text-center">
              <p className="text-gray-500 text-sm">Select a conversation or claim a request</p>
            </div>
          )}
        </div>
      </div>

      {showUsers && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={e => { if (e.target === e.currentTarget) setShowUsers(false); }}
        >
          <div className="bg-gray-800 border border-gray-700 rounded-2xl shadow-2xl w-full max-w-lg max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700 sticky top-0 bg-gray-800 rounded-t-2xl">
              <h2 className="text-white font-semibold text-lg">Agent Accounts</h2>
              <button
                onClick={() => setShowUsers(false)}
                className="text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg p-1.5 transition duration-150"
              >
                ✕
              </button>
            </div>

            <div className="px-6 py-4">
              {agentUsers.length === 0 ? (
                <p className="text-gray-500 text-sm py-4 text-center">No agents registered yet.</p>
              ) : (
                agentUsers.map(u => {
                  const isLocked = u.lockedUntil && new Date(u.lockedUntil) > new Date();
                  return (
                    <div
                      key={u.id}
                      className="flex items-center justify-between py-3 border-b border-gray-700 last:border-0"
                    >
                      <div>
                        {(u.firstName || u.lastName) && (
                          <div className="text-white text-sm font-medium">
                            {[u.firstName, u.lastName].filter(Boolean).join(' ')}
                          </div>
                        )}
                        <div className="text-gray-400 text-xs">{u.email}</div>
                        <div className={`text-xs mt-0.5 ${
                          !u.isActive ? 'text-red-400' : isLocked ? 'text-orange-400' : 'text-green-400'
                        }`}>
                          {!u.isActive ? 'Deactivated' : isLocked ? 'Locked (awaiting email unlock)' : 'Active'}
                        </div>
                      </div>
                      <button
                        onClick={() => u.isActive ? deactivateUser(u.id) : activateUser(u.id)}
                        className={`text-sm font-medium px-4 py-1.5 rounded-lg transition duration-150 min-w-[90px]
                          focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800
                          ${u.isActive
                            ? 'bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 focus:ring-red-500'
                            : 'bg-green-500/10 text-green-400 hover:bg-green-500/20 border border-green-500/30 focus:ring-green-500'
                          }`}
                      >
                        {u.isActive ? 'Deactivate' : 'Activate'}
                      </button>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
