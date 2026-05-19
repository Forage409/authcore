#!/usr/bin/env bash
# AuthCore 一键启动 (Mac / Linux)
set -e
cd "$(dirname "$0")"

if [ ! -f "backend/.env" ]; then
  echo "[!] backend/.env 不存在"
  exit 1
fi

if grep -q "nx_your_api_key_here" backend/.env; then
  echo "[!] 请先编辑 backend/.env，把 AUTHCORE_API_KEY 改为你的真实 Key"
  echo "    获取地址: https://auth.miaogou.site"
  exit 1
fi

if [ ! -d "backend/node_modules" ]; then
  echo "[*] 首次启动，安装依赖中..."
  npm install --prefix backend
fi

echo "[*] 启动 AuthCore..."
exec npm start --prefix backend
