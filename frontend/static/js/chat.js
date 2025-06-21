// Connect to Socket.IO
const socket = io();

const chatBox = document.getElementById('chat-box');
const chatForm = document.getElementById('chat-form');
const messageInput = document.getElementById('message-input');

// Render a message in the chat box
function addMessage(msg) {
  // Defensive check: Only add message if it's for the current room
  if (window.room && msg.room_slug !== window.room.slug) {
    return; 
  }

  const div = document.createElement('div');
  div.classList.add('message-row');
  
  // Add 'me' class if the message is from the current user
  if (msg.username === window.currentUser) {
      div.classList.add('me');
  }

  // Avatar bubble
  const avatar = document.createElement('div');
  avatar.className = 'chat-avatar';
  avatar.textContent = msg.username.charAt(0).toUpperCase();

  // Message content bubble
  const messageBubble = document.createElement('p');
  messageBubble.className = 'message-bubble';
  if (msg.username === window.currentUser) {
      messageBubble.classList.add('me');
  }
  messageBubble.textContent = msg.content;
  
  // Timestamp
  const meta = document.createElement('div');
  meta.className = 'message-meta';
  meta.textContent = new Date(msg.timestamp).toLocaleTimeString();
  
  // Assemble message
  const messageContentWrapper = document.createElement('div');
  messageContentWrapper.style.width = '100%';
  messageContentWrapper.appendChild(messageBubble);
  messageContentWrapper.appendChild(meta);

  div.appendChild(avatar);
  div.appendChild(messageContentWrapper);
  
  chatBox.appendChild(div);
  chatBox.scrollTop = chatBox.scrollHeight;
}

// Receive chat history
socket.on('chat_history', function(messages) {
  chatBox.innerHTML = '';
  messages.forEach(addMessage);
});

// Receive new message
socket.on('new_message', function(msg) {
  addMessage(msg);
});

// Send message
chatForm.addEventListener('submit', function(e) {
  e.preventDefault();
  const content = messageInput.value.trim();
  if (content && window.room && window.room.slug) {
    socket.emit('send_message', { 
        content: content, 
        room_slug: window.room.slug 
    });
    messageInput.value = '';
  }
});

// Real-time room list rendering
function renderRoomList(rooms) {
  const roomList = document.getElementById('room-list');
  if (!roomList) return;
  roomList.innerHTML = '';
  rooms.forEach(room => {
    const a = document.createElement('a');
    a.href = `/chat/room/${room.slug}`;
    a.className = 'badge-room btn btn-outline-primary btn-sm me-2 mb-2';
    a.textContent = room.name;
    if (window.room && window.room.slug === room.slug) {
      a.classList.add('active');
      a.style.background = 'var(--color-accent)';
      a.style.color = '#23262f';
      a.style.fontWeight = '700';
    }
    roomList.appendChild(a);
  });
}
socket.on('room_list', renderRoomList);

// Initial setup on page load
document.addEventListener('DOMContentLoaded', () => {
    // Request the list of rooms
    socket.emit('get_rooms');
    
    // If we are in a specific room, join it and get its history
    if (window.room && window.room.slug) {
        socket.emit('join_room', { room_slug: window.room.slug });
        socket.emit('get_chat_history', { room_slug: window.room.slug });
    }
}); 