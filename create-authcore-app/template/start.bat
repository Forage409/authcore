@echo off
chcp 65001 >nul
REM AuthCore 一键启动 (Windows)
setlocal

if not exist "backend\.env" (
  echo [!] backend\.env 不存在
  exit /b 1
)

findstr /C:"nx_your_api_key_here" backend\.env >nul && (
  echo [!] 请先编辑 backend\.env，把 AUTHCORE_API_KEY 改为你的真实 Key
  echo     获取地址: https://auth.miaogou.site
  pause
  exit /b 1
)

if not exist "backend\node_modules" (
  echo [*] 首次启动，安装依赖中...
  call npm install --prefix backend
  if errorlevel 1 (
    echo [!] 依赖安装失败
    exit /b 1
  )
)

echo [*] 启动 AuthCore...
call npm start --prefix backend
endlocal
