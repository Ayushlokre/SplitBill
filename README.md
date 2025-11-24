# Split Bill App - Full Stack

A complete expense splitting application with Next.js backend and React frontend.

## Project Structure

```
split-bill-app/
├── backend/          # Next.js Backend (Port 3000)
│   ├── app/          # API routes & pages
│   ├── prisma/       # Database schema
│   ├── lib/          # Utilities
│   └── .env          # Backend configuration
│
└── frontend/         # React Frontend (Port 5173)
    ├── src/          # React components & pages
    ├── public/       # Static assets
    └── .env          # Frontend configuration
```

## Quick Start

### 1. Start Backend

```bash
cd backend
npm install
npx prisma generate
npx prisma db push
npm run dev
```

Backend runs on: **http://localhost:3000**

### 2. Start Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on: **http://localhost:5173**

## Environment Setup

### Backend (.env)
```env
DATABASE_URL="postgresql://postgres:YOUR_PASSWORD@localhost:5432/splitbill"
NEXTAUTH_SECRET="your-secret-key"
NEXTAUTH_URL="http://localhost:3000"
```

### Frontend (.env)
```env
VITE_API_URL="http://localhost:3000"
```

## Features

- ✅ User authentication (register/login)
- ✅ Create and manage groups
- ✅ Invite members by email
- ✅ Add and split expenses
- ✅ Real-time balance calculation
- ✅ Settle expenses

## Tech Stack

**Backend:**
- Next.js 15
- Prisma ORM
- PostgreSQL
- NextAuth.js v5

**Frontend:**
- React 18
- Vite
- React Router
- Radix UI
- Tailwind CSS

## Access the App

Once both servers are running, open: **http://localhost:5173**

## Documentation

- See `backend/README.md` for backend details
- See `QUICKSTART.md` for detailed setup instructions
