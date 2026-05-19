declare module 'nexus-auth-sdk/oidc-react' {
  import { Component, ReactNode, CSSProperties } from 'react';
  import { OidcClient, OidcTokens } from 'nexus-auth-sdk/oidc';

  export interface OidcProviderProps {
    clientId: string;
    redirectUri: string;
    issuer?: string;
    scope?: string;
    clientSecret?: string;
    children: ReactNode;
  }

  export interface OidcContextValue {
    client: OidcClient;
    tokens: OidcTokens | null;
    setTokens: (t: OidcTokens | null) => void;
    user: OidcTokens['user'] | null;
    setUser: (u: OidcTokens['user'] | null) => void;
    isSignedIn: boolean;
    signIn: () => Promise<void>;
    signOut: () => Promise<void>;
  }

  export interface OidcSignInButtonProps {
    children?: ReactNode;
    className?: string;
    style?: CSSProperties;
    onError?: (e: Error) => void;
  }

  export interface OidcCallbackProps {
    onComplete?: (tokens: OidcTokens) => void;
    onError?: (e: Error) => void;
    fallback?: ReactNode;
  }

  export function OidcProvider(props: OidcProviderProps): Component;
  export function useOidc(): OidcContextValue;
  export function OidcSignInButton(props: OidcSignInButtonProps): Component;
  export function OidcCallback(props: OidcCallbackProps): Component;
}
