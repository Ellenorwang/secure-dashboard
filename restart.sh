#!/bin/bash
PORT=3001
PID=$(lsof -ti :$PORT)

if [ -n "$PID" ]; then
  echo "Killing process on port $PORT (PID: $PID)"
  kill -9 $PID
fi

echo "Restarting server..."
node server.js
