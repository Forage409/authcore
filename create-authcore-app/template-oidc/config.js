// 在 https://auth.miaogou.site 控制台开应用、启用 OIDC、添加 redirect_uri:
//   http://localhost:3000/callback.html
// 然后把下面的 CLIENT_ID 改为你的 Client ID (= 应用 ID UUID)
//
// 注意：纯前端 SPA 必须使用公开客户端 + PKCE，不能保存 client_secret
// （任何放在浏览器代码中的密钥都会泄露给所有访客）
window.AUTHCORE_OIDC_CONFIG = {
  issuer: 'https://auth.miaogou.site',
  clientId: 'PUT_YOUR_CLIENT_ID_HERE',
  redirectUri: window.location.origin + '/callback.html',
  scope: 'openid email profile',
};
