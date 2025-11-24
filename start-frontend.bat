@echo off
echo ============================================
echo   Split Bill - Starting Frontend Server
echo ============================================
echo.

cd frontend

echo [1/2] Checking dependencies...
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
)

echo [2/2] Starting frontend server...
echo.
echo Frontend will run on: http://localhost:5173
echo.
call npm run dev
