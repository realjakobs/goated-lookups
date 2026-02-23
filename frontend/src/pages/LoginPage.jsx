import React, { useState, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../lib/api.js';

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [phase, setPhase] = useState('credentials'); // 'credentials' or 'otp'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [tempToken, setTempToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const otpInputRef = useRef(null);

  async function handleCredentials(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/auth/login', { email, password });
      if (data.requires2FA) {
        setTempToken(data.tempToken);
        setPhase('otp');
        setTimeout(() => otpInputRef.current?.focus(), 50);
      } else {
        login(data.token, data.user, data.refreshToken);
        navigate(data.user.role === 'ADMIN' ? '/admin' : '/agent', { replace: true });
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  async function handleOtp(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { data } = await api.post('/auth/verify-otp', { otp }, {
        headers: { Authorization: `Bearer ${tempToken}` },
      });
      login(data.token, data.user, data.refreshToken);
      navigate(data.user.role === 'ADMIN' ? '/admin' : '/agent', { replace: true });
    } catch (err) {
      setError(err.response?.data?.error || 'Verification failed');
    } finally {
      setLoading(false);
    }
  }

  function handleBackToLogin() {
    setPhase('credentials');
    setOtp('');
    setTempToken('');
    setError('');
  }

  if (phase === 'credentials') {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
        <div className="w-full max-w-md">
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold text-white tracking-tight">Goated Lookups</h1>
            <p className="mt-2 text-gray-400 text-sm">Sign in to your account</p>
          </div>

          <div className={`bg-gray-800 rounded-2xl shadow-2xl border p-8 transition-all duration-150 ${error ? 'border-red-500/60' : 'border-gray-700'}`}>
            {error && (
              <div className="mb-5 flex items-start gap-3 bg-red-500/15 border border-red-500/50 rounded-xl px-4 py-3">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5 text-red-400 shrink-0 mt-0.5">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
                </svg>
                <p className="text-red-300 text-sm font-medium">{error}</p>
              </div>
            )}
            <form onSubmit={handleCredentials} className="space-y-5">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1.5">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  required
                  placeholder="you@example.com"
                  className="w-full bg-gray-700 border border-gray-600 text-white placeholder-gray-500
                             rounded-lg px-4 py-2.5 text-sm
                             focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                             transition duration-150"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1.5">Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  placeholder="••••••••"
                  className="w-full bg-gray-700 border border-gray-600 text-white placeholder-gray-500
                             rounded-lg px-4 py-2.5 text-sm
                             focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                             transition duration-150"
                />
                <div className="mt-1.5 text-right">
                  <Link to="/forgot-password" className="text-blue-400 hover:text-blue-300 text-xs transition duration-150">
                    Forgot password?
                  </Link>
                </div>
              </div>

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
                    Signing in…
                  </span>
                ) : 'Sign In'}
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  // OTP verification phase
  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-white tracking-tight">Goated Lookups</h1>
          <p className="mt-2 text-gray-400 text-sm">Two-factor verification</p>
        </div>

        <div className="bg-gray-800 rounded-2xl shadow-2xl border border-gray-700 p-8">
          <p className="text-gray-300 text-sm mb-6">
            A 6-digit verification code has been sent to <strong className="text-white">{email}</strong>.
            Enter it below to complete sign-in.
          </p>
          <form onSubmit={handleOtp} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Verification Code</label>
              <input
                ref={otpInputRef}
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                autoComplete="one-time-code"
                value={otp}
                onChange={e => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                required
                placeholder="000000"
                className="w-full bg-gray-700 border border-gray-600 text-white placeholder-gray-500
                           rounded-lg px-4 py-2.5 text-center tracking-[0.3em] font-mono text-lg
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
              disabled={loading || otp.length !== 6}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed
                         text-white font-semibold rounded-lg px-4 py-2.5 text-sm
                         transition duration-150 focus:outline-none focus:ring-2 focus:ring-blue-500
                         focus:ring-offset-2 focus:ring-offset-gray-800"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                  </svg>
                  Verifying…
                </span>
              ) : 'Verify'}
            </button>

            <button
              type="button"
              onClick={handleBackToLogin}
              className="w-full text-gray-400 hover:text-gray-300 text-sm transition duration-150"
            >
              Back to sign in
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
