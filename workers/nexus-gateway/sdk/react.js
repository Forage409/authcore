/**
 * nexus-auth-sdk/react — React bindings for AuthCore
 *
 * <AuthCoreProvider apiKey="nx_xxx">
 *   <SignIn />
 *   <SignUp />        // ← v4.5+ 自动检测 effective 邮箱验证状态，无需手动传 prop
 * </AuthCoreProvider>
 *
 * 你也可以手动覆盖：<SignUp emailVerification={true|false} />
 */

const React = require('react');
const { AuthCore } = require('./index');

const AuthCoreContext = React.createContext(null);

function AuthCoreProvider({ apiKey, baseUrl, children }) {
  const [client] = React.useState(() => new AuthCore({ apiKey, baseUrl }));
  const [user, setUser] = React.useState(null);
  const [token, setToken] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  // 全局缓存 effective 邮箱验证状态（来自 /api/auth/config）— SignUp 会自动消费
  const [config, setConfig] = React.useState(null);

  // 挂载时拉一次 config — 应用启动即知道当前是否需要验证码
  React.useEffect(() => {
    let alive = true;
    client.getConfig().then(c => { if (alive) setConfig(c); }).catch(() => {});
    return () => { alive = false; };
  }, [client]);

  const value = React.useMemo(() => ({
    client,
    user, setUser,
    token, setToken,
    loading, setLoading,
    config, setConfig,
    isSignedIn: !!token,
    signOut: () => { setToken(null); setUser(null); },
  }), [client, user, token, loading, config]);

  return React.createElement(AuthCoreContext.Provider, { value }, children);
}

function useAuthCore() {
  const ctx = React.useContext(AuthCoreContext);
  if (!ctx) throw new Error('useAuthCore must be used within <AuthCoreProvider>');
  return ctx;
}

const inputStyle = { padding: '10px 14px', borderRadius: 8, border: '2px solid #c4b89e', fontSize: 14 };
const btnStyle = { padding: '10px 20px', background: '#19c8b9', color: '#fff', border: 'none', borderRadius: 50, fontWeight: 700, cursor: 'pointer', fontSize: 14 };
const oidcBtnStyle = {
  padding: '11px 16px', background: '#fff', color: '#19c8b9',
  border: '2px solid #19c8b9', borderRadius: 10, fontWeight: 800,
  cursor: 'pointer', fontSize: 14, width: '100%',
  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
};
const dividerStyle = { display: 'flex', alignItems: 'center', gap: 10, color: '#9f927d', fontSize: 11, fontWeight: 700, margin: '4px 0' };
const errStyle = { color: '#e05a5a', fontSize: 13, padding: '8px 12px', background: '#fee2e2', borderRadius: 8 };

/**
 * 自动检测：如果应用启用了 OIDC，渲染「用 AuthCore 登录」按钮。
 * 内部 lazy require oidc 子模块（避免未启用 OIDC 时也打包 OIDC 代码）。
 */
function OidcAutoButton({ config, label }) {
  if (!config || !config.oidc_enabled || !config.oidc_default_redirect_uri) return null;
  const trigger = async () => {
    try {
      const oidcMod = require('./oidc');
      const c = new oidcMod.OidcClient({
        clientId: config.client_id,
        redirectUri: config.oidc_default_redirect_uri,
        scope: 'openid email profile',
      });
      await c.signIn();
    } catch (e) {
      alert('启动 OIDC 登录失败：' + e.message);
    }
  };
  return React.createElement(React.Fragment, null,
    React.createElement('button', { type: 'button', onClick: trigger, style: oidcBtnStyle }, label || '用 AuthCore 登录'),
    React.createElement('div', { style: dividerStyle },
      React.createElement('div', { style: { flex: 1, height: 1, background: '#e4d9c2' } }),
      React.createElement('span', null, '或使用邮箱密码'),
      React.createElement('div', { style: { flex: 1, height: 1, background: '#e4d9c2' } })
    )
  );
}
const infoStyle = { color: '#16a34a', fontSize: 13, padding: '8px 12px', background: '#dcfce7', borderRadius: 8 };
const noticeStyle = { color: '#92400e', fontSize: 12, padding: '6px 10px', background: '#fef3c7', borderRadius: 8 };

function SignIn({ onSuccess, className }) {
  const { client, setUser, setToken, loading, setLoading } = useAuthCore();
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const result = await client.login({ email, password });
      setToken(result.token);
      setUser(result.user);
      onSuccess && onSuccess(result);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  const { config } = useAuthCore();
  return React.createElement('form', { onSubmit: handleSubmit, className, style: { display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 320 } },
    React.createElement(OidcAutoButton, { config }),
    error && React.createElement('div', { style: errStyle }, error),
    React.createElement('input', { type: 'email', placeholder: '邮箱', value: email, onChange: e => setEmail(e.target.value), required: true, style: inputStyle }),
    React.createElement('input', { type: 'password', placeholder: '密码', value: password, onChange: e => setPassword(e.target.value), required: true, style: inputStyle }),
    React.createElement('button', { type: 'submit', disabled: loading, style: btnStyle }, loading ? '登录中...' : '登录')
  );
}

/**
 * Sign-up form component.
 *
 * 默认行为（推荐）：自动从 /api/auth/config 检测是否需要邮箱验证。
 *   - require_email_verification = true  → 渲染「发送验证码 / 输入验证码」步骤
 *   - require_email_verification = false → 普通注册（无验证码 UI）
 *   - captcha_forced_off = true（社区邮件配额耗尽）→ 自动降级为无验证码注册，
 *     并显示一条说明，告知用户次日恢复
 *
 * 显式覆盖：传 emailVerification={true|false}，会忽略自动检测。
 */
function SignUp({ onSuccess, className, emailVerification }) {
  const { client, setUser, setToken, loading, setLoading, config } = useAuthCore();
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [username, setUsername] = React.useState('');
  const [code, setCode] = React.useState('');
  const [codeSent, setCodeSent] = React.useState(false);
  const [error, setError] = React.useState('');
  const [info, setInfo] = React.useState('');

  // Effective 状态：emailVerification prop 优先，否则用 Provider 拉到的 config
  // config 还没拉到时返回 null，表示"未知" — UI 应等待，避免闪烁
  const needVerify = emailVerification !== undefined
    ? !!emailVerification
    : (config === null ? null : !!config.require_email_verification);
  const quotaDegraded = config?.captcha_forced_off === true;

  const sendCode = async () => {
    setError(''); setInfo('');
    if (!email) { setError('请先填写邮箱'); return; }
    setLoading(true);
    try {
      const r = await client.sendCode({ email });
      setCodeSent(true);
      setInfo(r.email_sent ? ('验证码已发送至 ' + email) : '邮件发送失败，请重试');
    } catch (err) {
      // 后端在配额耗尽或 API Key 未启用时会返回 verification_disabled — 友好降级
      if (err.code === 'verification_disabled' || err.code === 'quota_exceeded') {
        setInfo('今日无需验证码，直接填写密码完成注册');
        setCodeSent(false);
      } else {
        setError(err.message);
      }
    }
    setLoading(false);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setInfo('');
    setLoading(true);
    try {
      if (needVerify) {
        if (!codeSent || !code) { setError('请先获取并填写邮箱验证码'); setLoading(false); return; }
        const v = await client.verifyCode({ email, code });
        if (!v.valid) { setError('验证码错误或已过期，请重新获取'); setLoading(false); return; }
      }
      const result = await client.register({ email, password, username });
      setToken(result.token);
      setUser(result.user);
      onSuccess && onSuccess(result);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  // config 未到达 → 占位 loader，避免开关闪烁
  if (needVerify === null) {
    return React.createElement('div', { className, style: { padding: 20, color: '#9f927d', fontSize: 13 } }, '加载中...');
  }

  const children = [];
  children.push(React.createElement(OidcAutoButton, { key: 'oidc', config, label: '用 AuthCore 一键注册' }));
  if (error) children.push(React.createElement('div', { key: 'e', style: errStyle }, error));
  if (info) children.push(React.createElement('div', { key: 'i', style: infoStyle }, info));
  if (quotaDegraded) children.push(React.createElement('div', { key: 'q', style: noticeStyle }, '今日社区邮件配额已用完，注册免验证码，明日恢复'));

  children.push(
    React.createElement('input', { key: 'u', type: 'text', placeholder: '用户名（选填）', value: username, onChange: e => setUsername(e.target.value), style: inputStyle }),
    React.createElement('input', { key: 'm', type: 'email', placeholder: '邮箱', value: email, onChange: e => setEmail(e.target.value), required: true, style: inputStyle })
  );
  if (needVerify) {
    children.push(
      React.createElement('button', { key: 'sc', type: 'button', onClick: sendCode, disabled: loading, style: { ...btnStyle, background: '#fff', color: '#19c8b9', border: '2px solid #19c8b9' } }, codeSent ? '重新发送验证码' : '发送验证码')
    );
    if (codeSent) {
      children.push(
        React.createElement('input', { key: 'c', type: 'text', placeholder: '6 位邮箱验证码', maxLength: 6, value: code, onChange: e => setCode(e.target.value.replace(/\D/g, '')), required: true, style: inputStyle })
      );
    }
  }
  children.push(
    React.createElement('input', { key: 'p', type: 'password', placeholder: '密码（8位+，含大小写和数字）', value: password, onChange: e => setPassword(e.target.value), required: true, style: inputStyle }),
    React.createElement('button', { key: 'b', type: 'submit', disabled: loading, style: btnStyle }, loading ? '注册中...' : '注册')
  );

  return React.createElement('form', { onSubmit: handleSubmit, className, style: { display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 320 } }, children);
}

module.exports = { AuthCoreProvider, useAuthCore, SignIn, SignUp };
