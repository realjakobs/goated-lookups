import React from 'react';

export default function ConversationList({ conversations, activeId, onSelect }) {
  return (
    <div className="w-60 shrink-0 bg-gray-800 border-r border-gray-700 flex flex-col overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-700 shrink-0">
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
          Conversations
        </span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {conversations.length === 0 && (
          <div className="px-4 py-4 text-gray-500 text-xs">No conversations yet</div>
        )}
        {conversations.map(conv => (
          <button
            key={conv.id}
            onClick={() => onSelect(conv.id)}
            className={`w-full px-4 py-3 text-left border-b border-gray-700/50 transition duration-150
              focus:outline-none focus:bg-gray-700
              ${conv.id === activeId
                ? 'bg-blue-600/20 border-l-2 border-l-blue-500'
                : 'hover:bg-gray-700/60'
              }`}
          >
            <div className="text-sm font-medium text-white">
              Request {conv.marxRequest?.id?.slice(-6) ?? conv.id.slice(-6)}
            </div>
            <div className="text-xs text-gray-400 mt-0.5">
              {conv.marxRequest?.status ?? 'OPEN'}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
