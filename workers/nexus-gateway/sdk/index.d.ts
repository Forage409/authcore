declare module 'nexus-auth-sdk' {
  interface AuthCoreConfig {
    /**
     * AuthCore API Key（nx_ 开头的密钥）。
     * - 后端用：必填。
     * - 前端代理模式：留空，配合 baseUrl 指向你自己后端的代理路径，SDK 不会附 X-API-Key 头。
     */
    apiKey?: string;
    /**
     * API 根路径。
     * - 后端用：留空，默认 https://auth.miaogou.site/api
     * - 前端代理模式：必填，指向你自己后端的代理路径（如 '/api/auth'），由你的后端附加 X-API-Key 转发到 AuthCore
     */
    baseUrl?: string;
  }

  interface RegisterParams {
    email: string;
    password: string;
    username?: string;
  }

  interface LoginParams {
    email: string;
    password: string;
  }

  interface AuthResponse {
    token: string;
    refreshToken?: string;
    user: {
      id: string;
      email: string;
      username: string;
    };
  }

  interface VerifyResponse {
    valid: boolean;
    user?: {
      id: string;
      email: string;
      username: string;
    };
  }

  interface ConfigResponse {
    /**
     * Effective 邮箱验证开关：已合并社区邮件配额耗尽（captcha_forced_off）。
     * SDK 应据此值决定是否渲染验证码 UI。
     */
    require_email_verification: boolean;
    /**
     * 当前 API Key 的验证码是否因社区每日邮件配额耗尽被系统暂时强制关闭。
     * 为 true 时 require_email_verification 一定为 false；次日 00:00 (北京) 自动恢复。
     */
    captcha_forced_off: boolean;
    password_policy: {
      min_length: number;
      require_upper: boolean;
      require_lower: boolean;
      require_digit: boolean;
    };
    jwt_ttl_seconds: number;
    refresh_ttl_seconds: number;
  }

  export class AuthCore {
    constructor(config: AuthCoreConfig);
    /** 拉取 effective 配置；60 秒内自带缓存，传 { noCache: true } 强制刷新 */
    getConfig(opts?: { noCache?: boolean }): Promise<ConfigResponse>;
    register(params: RegisterParams): Promise<AuthResponse>;
    login(params: LoginParams): Promise<AuthResponse>;
    verify(token: string): Promise<VerifyResponse>;
    /** OIDC access_token 验证，返回 userinfo */
    verifyOidc(accessToken: string): Promise<{ sub: string; email?: string; name?: string; picture?: string; email_verified?: boolean }>;
    /**
     * 统一 token 校验：先尝试 JWT，失败降级 OIDC userinfo。
     * 让接入方一个方法搞定混合用户群（password 注册用户 + OIDC 授权用户共存）。
     * @returns { valid, user?: { id, email, username }, source?: 'jwt' | 'oidc' }
     */
    verifyAny(token: string): Promise<{ valid: boolean; user?: { id: string; email: string; username: string }; source?: 'jwt' | 'oidc' }>;
    refresh(refreshToken: string): Promise<{ token: string; refreshToken: string }>;
    /** OIDC refresh_token 续期 */
    refreshOidc(refreshToken: string, clientId: string): Promise<{ access_token: string; refresh_token?: string; expires_in: number; token_type: string }>;
    revoke(refreshToken: string): Promise<{ success: boolean }>;
    /** OIDC refresh_token 撤销 */
    revokeOidc(refreshToken: string, clientId: string): Promise<{ success: boolean }>;
    sendCode(params: { email: string }): Promise<{ success: boolean; email_sent: boolean; expires_in: number }>;
    verifyCode(params: { email: string; code: string }): Promise<{ valid: boolean; error?: string }>;
    /**
     * 注册"会话被撤销"回调；任意 SDK 调用 401 时触发。
     * 用于在用户从 user.miaogou.site 撤销授权后，让第三方应用自动登出。
     * @returns 取消订阅函数
     */
    onSessionRevoked(cb: () => void): () => void;
    /**
     * 启动轻量会话轮询：每 intervalMs 静默 verify(token)，失败时触发 onSessionRevoked。
     * 默认 60s 一次；传 { oidc: true } 走 OIDC userinfo 路径。返回 stop 函数。
     */
    startSessionWatch(token: string, opts?: { intervalMs?: number; oidc?: boolean }): () => void;
  }

  /**
   * 封禁类异常（5.9.0+）。SDK 在响应 403 + error 匹配时抛出对应子类。
   * 用 `instanceof` 判断，免去硬编码 error string：
   *   try { await auth.login({ email, password }); }
   *   catch (e) {
   *     if (e instanceof AccountBannedError) showBannedUI(e.reason);
   *     else throw e;
   *   }
   */
  export class BannedError extends Error {
    code: string;       // 'account_banned' | 'api_key_banned' | 'api_key_owner_banned' | 'app_banned'
    status: 403;
    reason: string;     // 站长设置的具体封禁原因，可直接展示给用户
  }
  export class AccountBannedError extends BannedError {}
  export class ApiKeyBannedError extends BannedError {}
  export class ApiKeyOwnerBannedError extends BannedError {}
  export class AppBannedError extends BannedError {}
}
