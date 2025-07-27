const socket = io();

const form = document.getElementById('chat-form');
const input = document.getElementById('chat-input');
const messages = document.getElementById('chat-messages');

form.addEventListener('submit', function(e) {
    e.preventDefault();
    const text = input.value.trim();
    if (text) {
        socket.emit('chat_message', { message: text });
        input.value = '';
    }
});

socket.on('chat_message', function(data) {
    const msg = document.createElement('div');
    msg.textContent = `${data.username}: ${data.message}`;
    messages.appendChild(msg);
    messages.scrollTop = messages.scrollHeight;
});
