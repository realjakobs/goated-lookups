import React from 'react';

export default function AdminQueue({ requests, onClaim, onResolve }) {
  return (
    <div className="w-72 shrink-0 bg-gray-800 border-r border-gray-700 flex flex-col overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-700 shrink-0 flex items-center justify-between">
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
          MARx Queue
        </span>
        <span className="bg-gray-700 text-gray-300 text-xs font-medium px-2 py-0.5 rounded-full">
          {requests.length}
        </span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {requests.length === 0 && (
          <div className="px-4 py-4 text-gray-500 text-xs">Queue is empty</div>
        )}
        {requests.map(req => (
          <div key={req.id} className="px-4 py-3 border-b border-gray-700/50">
            <div className="text-sm font-medium text-white mb-1">
              Request {req.id.slice(-8)}
            </div>
            <div className="text-xs text-gray-400 mb-2.5 space-y-0.5">
              <div>Agent: {req.agent?.email}</div>
              <div>{new Date(req.createdAt).toLocaleString()}</div>
            </div>
            <div className="flex gap-2">
              {req.status === 'PENDING' && (
                <button
                  onClick={() => onClaim(req.id)}
                  className="bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium
                             px-3 py-1.5 rounded-lg transition duration-150
                             focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800"
                >
                  Claim
                </button>
              )}
              {req.status === 'CLAIMED' && (
                <button
                  onClick={() => onResolve(req.id)}
                  className="bg-green-600 hover:bg-green-700 text-white text-xs font-medium
                             px-3 py-1.5 rounded-lg transition duration-150
                             focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 focus:ring-offset-gray-800"
                >
                  Resolve
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
