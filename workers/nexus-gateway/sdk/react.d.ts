declare module 'nexus-auth-sdk/react' {
  import { AuthCoreConfig, AuthResponse, ConfigResponse } from 'nexus-auth-sdk';
  import { Component, ReactNode } from 'react';

  interface AuthCoreContextValue {
    client: import('nexus-auth-sdk').AuthCore;
    user: AuthResponse['user'] | null;
    setUser: (user: AuthResponse['user'] | null) => void;
    token: string | null;
    setToken: (token: string | null) => void;
    loading: boolean;
    setLoading: (loading: boolean) => void;
    /** Provider 挂载时自动拉取的 effective 配置；首次拉到前为 null */
    config: ConfigResponse | null;
    setConfig: (config: ConfigResponse | null) => void;
    isSignedIn: boolean;
    signOut: () => void;
  }

  interface ProviderProps {
    apiKey: string;
    baseUrl?: string;
    children: ReactNode;
  }

  interface FormProps {
    onSuccess?: (result: AuthResponse) => void;
    className?: string;
  }

  interface SignUpProps extends FormProps {
    /**
     * 显式覆盖邮箱验证 UI。不传时 SDK 自动从 /api/auth/config 检测：
     *  - 开发者后台未开 → 普通注册
     *  - 开了但社区邮件配额耗尽（captcha_forced_off） → 自动降级为普通注册，并显示一条小提示
     */
    emailVerification?: boolean;
  }

  export function AuthCoreProvider(props: ProviderProps): Component;
  export function useAuthCore(): AuthCoreContextValue;
  export function SignIn(props: FormProps): Component;
  export function SignUp(props: SignUpProps): Component;
}
