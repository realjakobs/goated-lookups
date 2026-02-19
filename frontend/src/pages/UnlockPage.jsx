import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../lib/api.js';

export default function UnlockPage() {
  const { token } = useParams();
  const navigate = useNavigate();

  const [tokenValid, setTokenValid] = useState(null); // null=checking, true, false
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
    return <p style={{ margin: '80px auto', maxWidth: 400, padding: '0 16px' }}>Validating link…</p>;
  }

  if (tokenValid === false) {
    return (
      <div style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
        <h1>Goated Lookups</h1>
        <p style={{ color: 'red' }}>
          This unlock link is invalid or has expired. Please contact your administrator to have your account unlocked.
        </p>
      </div>
    );
  }

  if (success) {
    return (
      <div style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
        <h1>Goated Lookups</h1>
        <p style={{ color: 'green' }}>
          Your account has been unlocked. Redirecting to login…
        </p>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
      <h1>Goated Lookups</h1>
      <h2>Unlock Your Account</h2>
      <p>Answer your security question to regain access.</p>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', marginBottom: 4 }}>{securityQuestion}</label>
          <input
            type="text"
            value={answer}
            onChange={e => setAnswer(e.target.value)}
            required
            autoFocus
            style={{ display: 'block', width: '100%' }}
          />
        </div>
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <button type="submit" disabled={loading}>
          {loading ? 'Unlocking…' : 'Unlock Account'}
        </button>
      </form>
    </div>
  );
}
