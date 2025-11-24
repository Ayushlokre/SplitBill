@echo off
echo ============================================
echo   Split Bill - Starting Backend Server
echo ============================================
echo.

cd backend

echo [1/4] Checking dependencies...
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
)

echo [2/4] Generating Prisma client...
call npx prisma generate

echo [3/4] Checking database...
call npx prisma db push

echo [4/4] Starting backend server...
echo.
echo Backend will run on: http://localhost:3000
echo.
call npm run dev
