import React, { useEffect, useState } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../lib/api.js';
import ConversationList from '../components/ConversationList.jsx';
import MessageList from '../components/MessageList.jsx';
import MessageInput from '../components/MessageInput.jsx';
import { useMessageSound } from '../hooks/useMessageSound.js';
import BellButton from '../components/BellButton.jsx';

export default function AgentPage() {
  const { user, token, logout } = useAuth();
  const [conversations, setConversations] = useState([]);
  const [activeConvId, setActiveConvId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  const { soundEnabled, toggleSound, notify } = useMessageSound();

  useEffect(() => {
    const s = io(import.meta.env.VITE_API_URL || '', { auth: { token } });
    setSocket(s);
    return () => s.disconnect();
  }, [token]);

  useEffect(() => {
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
      if (msg.conversationId === activeConvId) {
        setMessages(prev => [...prev, msg]);
        if (msg.sender?.id !== user.id) notify();
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

  async function submitRequest() {
    const { data } = await api.post('/admin/request');
    const convRes = await api.get('/conversations');
    setConversations(convRes.data);
    alert(`MARx request submitted (ID: ${data.id})`);
  }

  async function sendMessage(content) {
    const { data } = await api.post(`/messages/${activeConvId}`, { content });
    setMessages(prev => [...prev, data]);
  }

  return (
    <div className="flex h-screen flex-col bg-gray-900">
      <header className="flex items-center justify-between px-5 py-3 bg-gray-800 border-b border-gray-700 shrink-0">
        <span className="font-semibold text-white">
          Goated Lookups
          <span className="ml-2 text-gray-400 font-normal text-sm">— Agent</span>
          <span className="ml-1 text-gray-500 text-xs">({user.email})</span>
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={submitRequest}
            className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium
                       px-4 py-1.5 rounded-lg transition duration-150
                       focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800"
          >
            + New MARx Request
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
        <ConversationList
          conversations={conversations}
          activeId={activeConvId}
          onSelect={setActiveConvId}
        />
        <div className="flex flex-1 flex-col overflow-hidden">
          {activeConvId ? (
            <>
              <MessageList messages={messages} currentUserId={user.id} />
              <MessageInput onSend={sendMessage} />
            </>
          ) : (
            <div className="m-auto text-center">
              <p className="text-gray-500 text-sm">Select a conversation to start messaging</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
