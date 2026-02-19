import React from 'react';

export default function BellButton({ enabled, onToggle }) {
  return (
    <button
      onClick={onToggle}
      title={enabled ? 'Mute notifications' : 'Unmute notifications'}
      className="relative flex items-center justify-center w-9 h-9 rounded-lg
                 text-gray-400 hover:text-white hover:bg-gray-700
                 transition duration-150 focus:outline-none focus:ring-2
                 focus:ring-gray-500 focus:ring-offset-2 focus:ring-offset-gray-800"
      aria-label={enabled ? 'Mute notifications' : 'Unmute notifications'}
    >
      {enabled ? (
        /* Bell ringing — animated */
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="bell-ring w-5 h-5"
        >
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
          <path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
      ) : (
        /* Bell muted — static with a diagonal slash */
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="w-5 h-5 opacity-50"
        >
          <path d="M13.73 21a2 2 0 0 1-3.46 0" />
          <path d="M18.63 13A17.89 17.89 0 0 1 18 8" />
          <path d="M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14" />
          <path d="M18 8a6 6 0 0 0-9.33-5" />
          <line x1="2" y1="2" x2="22" y2="22" />
        </svg>
      )}
    </button>
  );
}
