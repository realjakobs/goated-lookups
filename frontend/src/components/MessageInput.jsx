import React, { useState, useRef, useEffect, useCallback } from 'react';

export default function MessageInput({ onSend, droppedFile }) {
  const [value, setValue] = useState('');
  const [pendingFile, setPendingFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [sending, setSending] = useState(false);
  const fileInputRef = useRef(null);

  // Accept a file dropped from the parent (drag-and-drop over the chat area)
  useEffect(() => {
    if (droppedFile) {
      setFile(droppedFile);
    }
  }, [droppedFile]);

  function setFile(file) {
    if (!file) return;
    setPendingFile(file);
    setPreviewUrl(URL.createObjectURL(file));
  }

  function clearFile() {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPendingFile(null);
    setPreviewUrl(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  }

  function handleFileChange(e) {
    const file = e.target.files?.[0];
    if (file) setFile(file);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const trimmed = value.trim();
    if (!trimmed && !pendingFile) return;
    setSending(true);
    try {
      await onSend(trimmed, pendingFile);
      setValue('');
      clearFile();
    } finally {
      setSending(false);
    }
  }

  // Allow dropping directly onto the input bar
  const handleDrop = useCallback((e) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file && file.type.startsWith('image/')) setFile(file);
  }, []);

  const canSend = (value.trim().length > 0 || !!pendingFile) && !sending;

  return (
    <div
      className="shrink-0 bg-gray-800 border-t border-gray-700"
      onDragOver={e => e.preventDefault()}
      onDrop={handleDrop}
    >
      {/* Image preview */}
      {previewUrl && (
        <div className="px-4 pt-3 flex items-start gap-2">
          <div className="relative">
            <img
              src={previewUrl}
              alt="Preview"
              className="w-20 h-20 object-cover rounded-lg border border-gray-600"
            />
            <button
              type="button"
              onClick={clearFile}
              className="absolute -top-1.5 -right-1.5 w-5 h-5 bg-gray-900 border border-gray-600
                         rounded-full text-gray-400 hover:text-white text-xs
                         flex items-center justify-center transition duration-150"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      <form
        onSubmit={handleSubmit}
        className="flex items-center gap-3 px-4 py-3"
      >
        {/* Hidden file input */}
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={handleFileChange}
        />

        {/* Paperclip button */}
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          className="text-gray-400 hover:text-white p-1.5 rounded-lg hover:bg-gray-700
                     transition duration-150 focus:outline-none flex-shrink-0"
          title="Attach image"
        >
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"
            className="w-5 h-5">
            <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66L9.41 17.41a2 2 0 0 1-2.83-2.83l8.49-8.48" />
          </svg>
        </button>

        <input
          type="text"
          value={value}
          onChange={e => setValue(e.target.value)}
          placeholder="Type a message…"
          className="flex-1 bg-gray-700 border border-gray-600 text-white placeholder-gray-500
                     rounded-full px-4 py-2 text-sm
                     focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                     transition duration-150"
        />

        <button
          type="submit"
          disabled={!canSend}
          className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:text-gray-500 disabled:cursor-not-allowed
                     text-white font-medium px-5 py-2 rounded-full text-sm
                     transition duration-150 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800
                     flex items-center gap-2 min-w-[72px] justify-center"
        >
          {sending ? (
            <svg className="animate-spin w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
          ) : 'Send'}
        </button>
      </form>
    </div>
  );
}
