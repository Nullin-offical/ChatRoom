// Private Messaging Client Logic
const socket = io();

const chatBox = document.getElementById('chat-box');
const searchForm = document.getElementById('user-search-form');
const searchInput = document.getElementById('user-search-input');
const chatForm = document.getElementById('chat-form');
const messageInput = document.getElementById('message-input');

// Helper to render message bubbles
function addMessage(msg) {
  const div = document.createElement('div');
  div.classList.add('message-row');
  if (msg.username === window.currentUser) div.classList.add('me');

  const avatar = document.createElement('a');
  avatar.href = `/user/${msg.username}`;
  avatar.className = 'chat-avatar';
  avatar.textContent = msg.username.charAt(0).toUpperCase();

  const bubble = document.createElement('p');
  bubble.className = 'message-bubble';
  if (msg.username === window.currentUser) bubble.classList.add('me');
  bubble.textContent = msg.content;

  const meta = document.createElement('div');
  meta.className = 'message-meta';
  meta.textContent = new Date(msg.timestamp).toLocaleTimeString();

  const wrapper = document.createElement('div');
  wrapper.style.width = '100%';
  wrapper.appendChild(bubble);
  wrapper.appendChild(meta);

  div.appendChild(avatar);
  div.appendChild(wrapper);

  chatBox.appendChild(div);
  chatBox.scrollTop = chatBox.scrollHeight;
}

// Receive history
socket.on('pm_history', msgs => {
  chatBox.innerHTML = '';
  msgs.forEach(addMessage);
});

// Receive new pm
socket.on('new_pm', addMessage);

// If a targetUser is defined, join & request history
if (window.targetUser) {
  socket.emit('join_pm', { username: window.targetUser });
  socket.emit('get_pm_history', { username: window.targetUser });
}

// Sending messages
if (chatForm) {
  chatForm.addEventListener('submit', e => {
    e.preventDefault();
    const content = messageInput.value.trim();
    if (!content) return;
    socket.emit('send_pm', { receiver_username: window.targetUser, content });
    messageInput.value = '';
  });
}

// Search form handler
if (searchForm && !window.targetUser) {
  searchForm.addEventListener('submit', async e => {
    e.preventDefault();
    const username = searchInput.value.trim();
    if (!username) return;
    // Verify user exists via API then redirect
    try {
      const res = await fetch(`/api/search_users?q=${encodeURIComponent(username)}`);
      const list = await res.json();
      if (list.includes(username)) {
        window.location.href = `/pm/${username}`;
      } else {
        alert('User not found.');
      }
    } catch (err) {
      console.error(err);
    }
  });

  // Auto-complete suggestions (basic)
  let debounceTimer;
  searchInput.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    const query = searchInput.value.trim();
    if (!query) return;
    debounceTimer = setTimeout(async () => {
      try {
        const res = await fetch(`/api/search_users?q=${encodeURIComponent(query)}`);
        const users = await res.json();
        // simple datalist population
        let datalist = document.getElementById('user-options');
        if (!datalist) {
          datalist = document.createElement('datalist');
          datalist.id = 'user-options';
          document.body.appendChild(datalist);
          searchInput.setAttribute('list', 'user-options');
        }
        datalist.innerHTML = users.map(u => `<option value="${u}"></option>`).join('');
      } catch(err) { console.error(err); }
    }, 300);
  });
}