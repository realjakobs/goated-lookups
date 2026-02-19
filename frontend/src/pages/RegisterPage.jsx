import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../lib/api.js';

const inputCls = `w-full bg-gray-700 border border-gray-600 text-white placeholder-gray-500
  rounded-lg px-4 py-2.5 text-sm
  focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
  transition duration-150`;

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

export default function RegisterPage() {
  const { token } = useParams();
  const { login } = useAuth();
  const navigate = useNavigate();

  const [questions, setQuestions] = useState([]);
  const [inviteValid, setInviteValid] = useState(null);
  const [form, setForm] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    securityQuestion: '',
    securityAnswer: '',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function init() {
      try {
        const [inviteRes, questionsRes] = await Promise.all([
          api.get(`/auth/invite/${token}`),
          api.get('/auth/security-questions'),
        ]);
        setInviteValid(inviteRes.data.valid);
        setQuestions(questionsRes.data.questions);
        setForm(f => ({ ...f, securityQuestion: questionsRes.data.questions[0] }));
      } catch {
        setInviteValid(false);
      }
    }
    init();
  }, [token]);

  function set(field) {
    return e => setForm(f => ({ ...f, [field]: e.target.value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    if (form.password !== form.confirmPassword) {
      return setError('Passwords do not match.');
    }
    setLoading(true);
    try {
      const { data } = await api.post('/auth/register', {
        email: form.email,
        password: form.password,
        inviteToken: token,
        securityQuestion: form.securityQuestion,
        securityAnswer: form.securityAnswer,
      });
      login(data.token, data.user, data.refreshToken);
      navigate('/agent', { replace: true });
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed.');
    } finally {
      setLoading(false);
    }
  }

  if (inviteValid === null) {
    return (
      <Shell>
        <p className="text-gray-400 text-sm text-center">Validating invite…</p>
      </Shell>
    );
  }

  if (inviteValid === false) {
    return (
      <Shell>
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">
          <p className="text-red-400 text-sm">
            This invite link is invalid or has expired. Please ask an admin to send you a new one.
          </p>
        </div>
      </Shell>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-white tracking-tight">Goated Lookups</h1>
          <p className="mt-2 text-gray-400 text-sm">Create your account</p>
        </div>

        <div className="bg-gray-800 rounded-2xl shadow-2xl border border-gray-700 p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Email</label>
              <input
                type="email"
                value={form.email}
                onChange={set('email')}
                required
                placeholder="you@example.com"
                className={inputCls}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Password</label>
              <input
                type="password"
                value={form.password}
                onChange={set('password')}
                required
                minLength={8}
                placeholder="Min. 8 characters"
                className={inputCls}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Confirm Password</label>
              <input
                type="password"
                value={form.confirmPassword}
                onChange={set('confirmPassword')}
                required
                placeholder="Re-enter your password"
                className={inputCls}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Security Question</label>
              <select
                value={form.securityQuestion}
                onChange={set('securityQuestion')}
                required
                className={`${inputCls} cursor-pointer`}
              >
                {questions.map(q => (
                  <option key={q} value={q}>{q}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1.5">Security Answer</label>
              <input
                type="text"
                value={form.securityAnswer}
                onChange={set('securityAnswer')}
                required
                placeholder="Your answer"
                className={inputCls}
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
                  Creating account…
                </span>
              ) : 'Create Account'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
