import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../lib/api.js';
import ConversationList from '../components/ConversationList.jsx';
import MessageList from '../components/MessageList.jsx';
import MessageInput from '../components/MessageInput.jsx';

export default function AgentPage() {
  const { user, token, logout } = useAuth();
  const [conversations, setConversations] = useState([]);
  const [activeConvId, setActiveConvId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);

  // Connect socket
  useEffect(() => {
    const s = io(import.meta.env.VITE_API_URL || '', { auth: { token } });
    setSocket(s);
    return () => s.disconnect();
  }, [token]);

  // Load conversations
  useEffect(() => {
    api.get('/conversations').then(r => setConversations(r.data));
  }, []);

  // Load messages when conversation changes
  useEffect(() => {
    if (!activeConvId) { setMessages([]); return; }
    api.get(`/messages/${activeConvId}`).then(r => setMessages(r.data));

    socket?.emit('join-conversation', activeConvId);
    return () => socket?.emit('leave-conversation', activeConvId);
  }, [activeConvId, socket]);

  // Real-time new messages
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

  async function submitRequest() {
    const { data } = await api.post('/admin/request');
    // Refresh conversations after request is created
    const convRes = await api.get('/conversations');
    setConversations(convRes.data);
    alert(`MARx request submitted (ID: ${data.id})`);
  }

  async function sendMessage(content) {
    const { data } = await api.post(`/messages/${activeConvId}`, { content });
    setMessages(prev => [...prev, data]);
  }

  return (
    <div style={{ display: 'flex', height: '100vh', flexDirection: 'column' }}>
      <header style={{ padding: '8px 16px', borderBottom: '1px solid #ccc', display: 'flex', justifyContent: 'space-between' }}>
        <span>Goated Lookups — Agent ({user.email})</span>
        <div>
          <button onClick={submitRequest} style={{ marginRight: 8 }}>+ New MARx Request</button>
          <button onClick={logout}>Logout</button>
        </div>
      </header>
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
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
            : <div style={{ margin: 'auto', color: '#888' }}>Select a conversation</div>
          }
        </div>
      </div>
    </div>
  );
}
