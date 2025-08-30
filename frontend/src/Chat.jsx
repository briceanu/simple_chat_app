import React, { useEffect, useState, useRef } from 'react';

export default function Chat() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const ws = useRef(null);
  const [connected, setConnected] = useState(false);

  // Replace this with your actual JWT token from login
  const token =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpb251dCIsInNjb3BlcyI6WyJhZG1pbiJdLCJleHAiOjE3NTY1OTgxMTR9.EJcmrmakeNJv28DF1P5aSzuCqkKnNHi3fCg1yqP8fkE';
  const connectWebSocket = () => {
    ws.current = new WebSocket(`ws://localhost:8000/ws?token=${token}`);

    ws.current.onopen = () => {
      console.log('Connected to WebSocket');
      setConnected(true);
    };

    ws.current.onmessage = (event) => {
      setMessages((prev) => [...prev, event.data]);
    };

    ws.current.onclose = () => {
      console.log('WebSocket disconnected. Reconnecting in 2s...');
      setConnected(false);
      setTimeout(connectWebSocket, 2000); // auto-reconnect after 2s
    };

    ws.current.onerror = (err) => {
      console.error('WebSocket error:', err);
      ws.current.close();
    };
  };

  useEffect(() => {
    connectWebSocket();

    return () => {
      ws.current && ws.current.close();
    };
  }, []);

  const sendMessage = (e) => {
    e.preventDefault();
    if (input.trim() !== '' && connected) {
      ws.current.send(input);
      setInput('');
    }
  };

  return (
    <div className='min-h-screen flex flex-col items-center justify-center bg-gray-100 p-6'>
      <div className='w-full max-w-md bg-white rounded-2xl shadow-lg p-6'>
        <h1 className='text-xl font-bold text-center mb-2'>Friends Chat</h1>

        <ul className='h-64 overflow-y-auto border rounded-lg p-3 mb-4 bg-gray-50'>
          {messages.map((msg, i) => (
            <li key={i} className='text-sm mb-1'>
              {msg}
            </li>
          ))}
        </ul>

        <form onSubmit={sendMessage} className='flex gap-2'>
          <input
            type='text'
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder='Type a message...'
            className='flex-grow border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500'
          />
          <button
            type='submit'
            className='bg-blue-500 hover:bg-blue-600 text-white rounded-lg px-4 py-2 text-sm'
          >
            Send
          </button>
        </form>
      </div>
    </div>
  );
}
