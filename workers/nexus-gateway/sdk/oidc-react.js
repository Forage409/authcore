/**
 * nexus-auth-sdk/oidc-react — React 绑定
 *
 * <OidcProvider clientId="..." redirectUri="...">
 *   <OidcSignInButton>用 AuthCore 登录</OidcSignInButton>
 *   <OidcCallback onComplete={(tokens) => navigate('/dashboard')} />
 * </OidcProvider>
 */
const React = require('react');
const { OidcClient } = require('./oidc');

const OidcContext = React.createContext(null);

function OidcProvider({ clientId, redirectUri, issuer, scope, clientSecret, children }) {
  const [client] = React.useState(() => new OidcClient({ clientId, redirectUri, issuer, scope, clientSecret }));
  const [tokens, setTokens] = React.useState(null);
  const [user, setUser] = React.useState(null);
  const value = React.useMemo(() => ({
    client, tokens, setTokens, user, setUser,
    isSignedIn: !!tokens,
    signIn: () => client.signIn(),
    signOut: async () => { await client.signOut(); setTokens(null); setUser(null); },
  }), [client, tokens, user]);
  return React.createElement(OidcContext.Provider, { value }, children);
}

function useOidc() {
  const ctx = React.useContext(OidcContext);
  if (!ctx) throw new Error('useOidc must be used within <OidcProvider>');
  return ctx;
}

const btnStyle = {
  display: 'inline-flex', alignItems: 'center', gap: 8,
  padding: '10px 18px', background: '#19c8b9', color: '#fff',
  border: 'none', borderRadius: 50, fontWeight: 700, cursor: 'pointer', fontSize: 14,
  boxShadow: '0 4px 0 0 #11a89b',
};

/** 触发 OIDC 登录跳转的按钮 */
function OidcSignInButton({ children = '用 AuthCore 登录', style, className, onError }) {
  const { client } = useOidc();
  const handle = async () => {
    try { await client.signIn(); }
    catch (e) { onError ? onError(e) : console.error(e); }
  };
  return React.createElement('button', { type: 'button', onClick: handle, className, style: { ...btnStyle, ...(style || {}) } }, children);
}

/**
 * 挂在 /callback 路由的组件。挂载即调 handleCallback，
 * 完成后调 onComplete({tokens, user})；失败调 onError(error)。
 */
function OidcCallback({ onComplete, onError, fallback }) {
  const { client, setTokens, setUser } = useOidc();
  const [error, setError] = React.useState(null);
  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await client.handleCallback();
        if (cancelled) return;
        setTokens(r);
        setUser(r.user);
        onComplete && onComplete(r);
      } catch (e) {
        if (cancelled) return;
        setError(e);
        onError && onError(e);
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  if (error) {
    return React.createElement('div', { style: { padding: 20, color: '#e05a5a', fontSize: 14 } }, '登录失败: ' + (error.message || String(error)));
  }
  return fallback || React.createElement('div', { style: { padding: 20, color: '#9f927d', fontSize: 14 } }, '登录中...');
}

module.exports = { OidcProvider, useOidc, OidcSignInButton, OidcCallback };
