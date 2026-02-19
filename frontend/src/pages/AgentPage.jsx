import React, { useEffect, useState, useRef } from 'react';
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
  const [dragActive, setDragActive] = useState(false);
  const [droppedFile, setDroppedFile] = useState(null);
  const dragCounterRef = useRef(0);

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

    // Admin claimed the request — refresh conversations so the status updates
    const onClaimedByAdmin = () => {
      api.get('/conversations').then(r => setConversations(r.data));
    };

    socket.on('new-message', onMessage);
    socket.on('messages-expired', onExpired);
    socket.on('request-claimed-by-admin', onClaimedByAdmin);
    return () => {
      socket.off('new-message', onMessage);
      socket.off('messages-expired', onExpired);
      socket.off('request-claimed-by-admin', onClaimedByAdmin);
    };
  }, [socket, activeConvId, user.id, notify]);

  async function submitRequest() {
    const { data } = await api.post('/admin/request');
    const convRes = await api.get('/conversations');
    setConversations(convRes.data);
    // Auto-navigate into the new conversation so agent can send info immediately
    setActiveConvId(data.conversation.id);
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
              <MessageList messages={messages} currentUserId={user.id} />
              <MessageInput onSend={sendMessage} droppedFile={droppedFile} />
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
