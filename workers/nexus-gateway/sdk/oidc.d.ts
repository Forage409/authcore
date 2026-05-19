declare module 'nexus-auth-sdk/oidc' {
  export interface OidcClientOptions {
    clientId: string;
    redirectUri: string;
    issuer?: string;
    scope?: string;
    /** 仅服务端可设；浏览器中传入将抛错 */
    clientSecret?: string;
    storageKey?: string;
  }

  export interface OidcUser {
    sub: string;
    email?: string;
    name?: string;
    picture?: string;
    email_verified?: boolean;
  }

  export interface OidcTokens {
    idToken: string;
    accessToken: string;
    refreshToken?: string;
    expiresIn?: number;
    scope?: string;
    user: OidcUser;
  }

  export class OidcClient {
    constructor(opts: OidcClientOptions);
    issuer: string;
    clientId: string;
    redirectUri: string;
    scope: string;

    /** 触发登录跳转（PKCE 公开客户端流程） */
    signIn(extra?: Record<string, string>): Promise<void>;
    /** 在 callback 页调用，完成 code 交换并校验 state/nonce/iss/aud */
    handleCallback(): Promise<OidcTokens>;
    /** 用 access_token 拉 userinfo；401 触发 onSessionRevoked */
    userInfo(accessToken?: string): Promise<OidcUser>;
    /** 单飞锁 refresh；400/401 触发 onSessionRevoked */
    refresh(refreshToken?: string): Promise<any>;
    /** 撤销 refresh_token 并清理本地状态 */
    signOut(): Promise<void>;
    /** 自动加 Bearer + 401 自动 refresh 重试一次 */
    authorizedFetch(url: string, init?: RequestInit): Promise<Response>;
    /** 注册"会话被撤销"回调；返回取消订阅函数 */
    onSessionRevoked(cb: () => void): () => void;
    /** 后台周期轮询 userinfo（毫秒，默认 60000）；返回 stop 函数 */
    startSessionWatch(intervalMs?: number): () => void;
    /** OpenID Connect discovery（带超时 + 失败短路）*/
    discovery(): Promise<any>;
    getAccessToken(): string | null;
    getIdToken(): string | null;
  }
}
