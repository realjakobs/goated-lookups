import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../lib/api.js';

export default function RegisterPage() {
  const { token } = useParams();
  const { login } = useAuth();
  const navigate = useNavigate();

  const [questions, setQuestions] = useState([]);
  const [inviteValid, setInviteValid] = useState(null); // null=checking, true, false
  const [form, setForm] = useState({
    email: '',
    password: '',
    confirmPassword: '',
    securityQuestion: '',
    securityAnswer: '',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Validate invite and load security questions on mount
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
    return <p style={{ margin: '80px auto', maxWidth: 400, padding: '0 16px' }}>Validating invite…</p>;
  }

  if (inviteValid === false) {
    return (
      <div style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
        <h1>Goated Lookups</h1>
        <p style={{ color: 'red' }}>
          This invite link is invalid or has expired. Please ask an admin to send you a new one.
        </p>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
      <h1>Goated Lookups</h1>
      <h2>Create your account</h2>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 12 }}>
          <label>Email</label>
          <input
            type="email"
            value={form.email}
            onChange={set('email')}
            required
            style={{ display: 'block', width: '100%', marginTop: 4 }}
          />
        </div>
        <div style={{ marginBottom: 12 }}>
          <label>Password</label>
          <input
            type="password"
            value={form.password}
            onChange={set('password')}
            required
            minLength={8}
            style={{ display: 'block', width: '100%', marginTop: 4 }}
          />
        </div>
        <div style={{ marginBottom: 12 }}>
          <label>Confirm Password</label>
          <input
            type="password"
            value={form.confirmPassword}
            onChange={set('confirmPassword')}
            required
            style={{ display: 'block', width: '100%', marginTop: 4 }}
          />
        </div>
        <div style={{ marginBottom: 12 }}>
          <label>Security Question</label>
          <select
            value={form.securityQuestion}
            onChange={set('securityQuestion')}
            required
            style={{ display: 'block', width: '100%', marginTop: 4 }}
          >
            {questions.map(q => (
              <option key={q} value={q}>{q}</option>
            ))}
          </select>
        </div>
        <div style={{ marginBottom: 16 }}>
          <label>Security Answer</label>
          <input
            type="text"
            value={form.securityAnswer}
            onChange={set('securityAnswer')}
            required
            style={{ display: 'block', width: '100%', marginTop: 4 }}
          />
        </div>
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <button type="submit" disabled={loading}>
          {loading ? 'Creating account…' : 'Create Account'}
        </button>
      </form>
    </div>
  );
}
