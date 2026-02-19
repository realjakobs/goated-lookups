import React, { useEffect, useRef } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext.jsx';
import LoginPage from './pages/LoginPage.jsx';
import AgentPage from './pages/AgentPage.jsx';
import AdminPage from './pages/AdminPage.jsx';
import RegisterPage from './pages/RegisterPage.jsx';
import UnlockPage from './pages/UnlockPage.jsx';

const IDLE_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

function IdleTimer() {
  const { user, logout } = useAuth();
  const timer = useRef(null);

  useEffect(() => {
    if (!user) return;

    function resetTimer() {
      clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        alert('You have been logged out due to inactivity.');
        logout();
      }, IDLE_TIMEOUT_MS);
    }

    const events = ['mousemove', 'keydown', 'mousedown', 'touchstart', 'scroll'];
    events.forEach(e => window.addEventListener(e, resetTimer));
    resetTimer();

    return () => {
      clearTimeout(timer.current);
      events.forEach(e => window.removeEventListener(e, resetTimer));
    };
  }, [user, logout]);

  return null;
}

function PrivateRoute({ children, requiredRole }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (requiredRole && user.role !== requiredRole) return <Navigate to="/" replace />;
  return children;
}

function RootRedirect() {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  return user.role === 'ADMIN'
    ? <Navigate to="/admin" replace />
    : <Navigate to="/agent" replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <IdleTimer />
        <Routes>
          <Route path="/" element={<RootRedirect />} />
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/agent"
            element={
              <PrivateRoute requiredRole="AGENT">
                <AgentPage />
              </PrivateRoute>
            }
          />
          <Route
            path="/admin"
            element={
              <PrivateRoute requiredRole="ADMIN">
                <AdminPage />
              </PrivateRoute>
            }
          />
          <Route path="/register/:token" element={<RegisterPage />} />
          <Route path="/unlock/:token" element={<UnlockPage />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
