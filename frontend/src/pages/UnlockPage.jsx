import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../lib/api.js';

function Shell({ children }) {
  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-white tracking-tight">Goated Lookups</h1>
        </div>
        <div className="bg-gray-800 rounded-2xl shadow-2xl border border-gray-700 p-8">
          {children}
        </div>
      </div>
    </div>
  );
}

export default function UnlockPage() {
  const { token } = useParams();
  const navigate = useNavigate();

  const [tokenValid, setTokenValid] = useState(null);
  const [securityQuestion, setSecurityQuestion] = useState('');
  const [answer, setAnswer] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.get(`/auth/unlock/${token}`)
      .then(r => {
        setTokenValid(true);
        setSecurityQuestion(r.data.securityQuestion);
      })
      .catch(() => setTokenValid(false));
  }, [token]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await api.post(`/auth/unlock/${token}`, { securityAnswer: answer });
      setSuccess(true);
      setTimeout(() => navigate('/login'), 3000);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to unlock account.');
    } finally {
      setLoading(false);
    }
  }

  if (tokenValid === null) {
    return (
      <Shell>
        <p className="text-gray-400 text-sm text-center">Validating link…</p>
      </Shell>
    );
  }

  if (tokenValid === false) {
    return (
      <Shell>
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">
          <p className="text-red-400 text-sm">
            This unlock link is invalid or has expired. Please contact your administrator to have your account unlocked.
          </p>
        </div>
      </Shell>
    );
  }

  if (success) {
    return (
      <Shell>
        <div className="bg-green-500/10 border border-green-500/30 rounded-lg px-4 py-3">
          <p className="text-green-400 text-sm">
            Your account has been unlocked. Redirecting to login…
          </p>
        </div>
      </Shell>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-white tracking-tight">Goated Lookups</h1>
          <p className="mt-2 text-gray-400 text-sm">Unlock your account</p>
        </div>

        <div className="bg-gray-800 rounded-2xl shadow-2xl border border-gray-700 p-8">
          <p className="text-gray-300 text-sm mb-6">Answer your security question to regain access.</p>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">
                {securityQuestion}
              </label>
              <input
                type="text"
                value={answer}
                onChange={e => setAnswer(e.target.value)}
                required
                autoFocus
                placeholder="Your answer"
                className="w-full bg-gray-700 border border-gray-600 text-white placeholder-gray-500
                           rounded-lg px-4 py-2.5 text-sm
                           focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                           transition duration-150"
              />
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-2.5">
                <p className="text-red-400 text-sm">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed
                         text-white font-semibold rounded-lg px-4 py-2.5 text-sm
                         transition duration-150 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-800"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                  </svg>
                  Unlocking…
                </span>
              ) : 'Unlock Account'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
