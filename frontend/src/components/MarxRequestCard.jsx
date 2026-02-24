import React from 'react';

export default function MarxRequestCard({ marxRequest }) {
  if (!marxRequest) return null;
  const { clientIdentifierType, clientIdentifier, clientIdType, clientId } = marxRequest;
  if (!clientIdentifier && !clientId) return null;

  return (
    <div className="shrink-0 bg-gray-800/60 border-b border-gray-700 px-4 py-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs">
      {clientIdentifierType && clientIdentifier && (
        <span>
          <span className="text-gray-500">{clientIdentifierType === 'NAME' ? 'Name' : 'DOB'}:</span>{' '}
          <span className="text-gray-300">{clientIdentifier}</span>
        </span>
      )}
      {clientIdType && clientId && (
        <span className="flex items-center gap-1.5">
          <span className="text-gray-500">{clientIdType}:</span>
          <span className="text-gray-300 font-mono tracking-wide">{clientId}</span>
          <button
            onClick={() => navigator.clipboard.writeText(clientId)}
            className="text-blue-400 hover:text-blue-300 underline transition duration-150"
          >
            Copy
          </button>
        </span>
      )}
    </div>
  );
}
