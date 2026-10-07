# MiniLocker frontend

React + Vite + Tailwind. In dev, `/api` is proxied to the control plane on `127.0.0.1:8000`.

    npm install
    npm run dev        # http://localhost:5173

Backend (separate terminal, from `backend/`): `python -m minilocker.api`

A running or finished task is addressable as `/#task=<id>`; reloading rejoins the stream.
