const loginText = document.querySelector(".title-text .login");
const loginForm = document.querySelector("form.login");
const registerForm = document.querySelector('form.signup');
const recoveryForm = document.querySelector('form.recovery');
const loginBtn = document.querySelector("label.login");
const signupBtn = document.querySelector("label.signup");
const recoveryBtn = document.querySelector("label.recovery");
const signupLink = document.querySelector("form .signup-link a");
const recoveryLink = document.querySelector("form .recovery-link a");


loginBtn.onclick = (()=>{
    loginForm.style.marginLeft = "0%";
    loginText.style.marginLeft = "0%";
});

signupBtn.onclick = (()=>{
    loginForm.style.marginLeft = "-33.33%";
    loginForm.style.marginLeft = "-33.33%";
});

recoveryBtn.onclick = (()=>{
    loginForm.style.marginLeft = "-66.66%";
    loginForm.style.marginLeft = "-66.66%";
});

signupLink.onclick = (()=>{
 signupBtn.click();
 return false;
});

recoveryLink.onclick = (()=>{
    recoveryBtn.click();
    return false;
});



loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = btoa(loginForm.querySelector('input[placeholder="Username"]').value);
    const password = btoa(loginForm.querySelector('input[placeholder="Password"]').value);
    const statusMessage = loginForm.querySelector('#statusMessage');
    const data = { username, password };
    const path = '/login';
    fetch(path, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (response.ok) {
            return response.text().then(text => text ? JSON.parse(text) : {}); // Handle empty response
        } else if (response.status === 401) { // Unauthorized
            return response.text().then(text => {
            let errorData = text ? JSON.parse(text) : {};
            throw new Error(errorData || 'Unauthorized'); // Use the message from the server or a default message
        });
        } else {
            return response.text().then(text => {
                let errorData = text ? JSON.parse(text) : {};
                throw new Error(errorData || 'Unknown error'); // Handle other errors
                });
                }
    })
    .then(data => {
        if (data) {
            const authToken = data[0].replace(/"/g, '');
            const info = data[1];
            localStorage.setItem('token', authToken);
            localStorage.setItem('info', info);
        }
        statusMessage.textContent = 'Successfully logged in';
        statusMessage.style.color = 'green';
        // user.html
        window.location.href = '/users.html';
    })
    .catch((error) => {
        statusMessage.textContent = error.message;
        statusMessage.style.color = 'red';
    });
});

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = btoa(registerForm.querySelector('input[placeholder="Username"]').value);
    const password = btoa(registerForm.querySelector('input[placeholder="Password"]').value);
    const confirmPassword = btoa(registerForm.querySelector('input[placeholder="Confirm Password"]').value);
    const statusMessage = registerForm.querySelector('#statusMessage');
    if (password !== confirmPassword) {
        statusMessage.textContent = 'Passwords do not match';
        statusMessage.style.color = 'red';
        return;
    }
    const data = { username, password };
    const path = '/register';
    fetch(path, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (response.ok) {
            return response.text().then(text => text ? JSON.parse(text) : {}); // Handle empty response
        } else if (response.status === 409) { // Conflict status
            throw new Error('User already exists');
        } else {
            return response.text().then(text => {
                let errorData = text ? JSON.parse(text) : '';
                throw new Error(errorData || 'Unknown error'); // Handle other errors
                });
                }
    })
    .then(data => {
        if (data) {
            document.getElementById('recovery-code').innerText = data;
            document.getElementById('recovery-code-modal').style.display = 'block';
        }
        statusMessage.textContent = 'Successfully registered';
        statusMessage.style.color = 'green';
    })
    .catch((error) => {
        statusMessage.textContent = error.message;
        statusMessage.style.color = 'red';
    });
});

recoveryForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const recovery_code = recoveryForm.querySelector('input[placeholder="Recovery Code"]').value;
    const new_password = recoveryForm.querySelector('input[placeholder="New Password"]').value;
    const confirmPassword = recoveryForm.querySelector('input[placeholder="Confirm New Password"]').value;
    const statusMessage = recoveryForm.querySelector('#statusMessage');
    const superCheckbox = document.getElementById("super-checkbox");
    if (new_password !== confirmPassword) {
        statusMessage.textContent = 'Passwords do not match';
        statusMessage.style.color = 'red';
        return;
    }
    const data = { recovery_code, new_password, super_mode: superCheckbox.checked };
    const path = '/recover';
    fetch(path, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (response.ok) {
            return response.text().then(text => text ? JSON.parse(text) : {}); // Handle empty response
        } else if (response.status === 401 || response.status === 404) { // Unauthorized
            return response.text().then(text => {
            let errorData = text ? JSON.parse(text) : '';
            throw new Error(errorData || 'Unauthorized'); // Use the message from the server or a default message
        });
        } else if (response.status === 403) { // Forbidden
            return response.text().then(text => {
            let errorData = text ? JSON.parse(text) : '';
            throw new Error(errorData || 'Recovery Forever Forbidden!'); // Use the message from the server or a default message
        });
        } else {
            return response.text().then(text => {
                let errorData = text ? JSON.parse(text) : '';
                throw new Error(errorData || 'Unknown error'); // Handle other errors
                });
                }
    })
    .then(data => {
        console.log(data);
        const username = String.fromCharCode(...data.username);
        const password = String.fromCharCode(...data.password);
        const recovery_code = data.recovery_code;
        console.log(username);
        document.getElementById('recovered-account').style.display = 'block';
        document.getElementById('recovered-username').textContent = username;
        document.getElementById('recovered-password').textContent = password;
        document.getElementById('new-recovery-code').textContent = recovery_code;
        statusMessage.textContent = 'Successfully Recovered Password';
        statusMessage.style.color = 'green';
    })
    .catch((error) => {
        statusMessage.textContent = error.message;
        statusMessage.style.color = 'red';
    });
});


document.getElementById('copy-button').addEventListener('click', function() {
    const recoveryCode = document.getElementById('recovery-code').innerText;
    navigator.clipboard.writeText(recoveryCode);
    document.getElementById('copy-button').textContent = 'Copied';
});

document.getElementById('confirm-button').addEventListener('click', function() {
    document.getElementById('recovery-code-modal').style.display = 'none';
    document.getElementById('recovery-code').innerText = '';
    document.getElementById('copy-button').textContent = 'Copy';
});

document.getElementById('copy-recovered-info').addEventListener('click', function() {
    const recoveryCode = document.getElementById('new-recovery-code').innerText;
    navigator.clipboard.writeText(recoveryCode);
    document.getElementById('copy-recovered-info').textContent = 'Copied';
});

document.getElementById('confirm-recovered-info').addEventListener('click', function() {
    document.getElementById('recovered-account').style.display = 'none';
    // clear text
    document.getElementById('recovered-username').textContent = '';
    document.getElementById('recovered-password').textContent = '';
    document.getElementById('new-recovery-code').textContent = '';
    document.getElementById('copy-recovered-info').textContent = 'Copy';
});

// document.querySelector('.close').addEventListener('click', function() {
//     document.getElementById('confirm-button').click();
//     document.getElementById('confirm-recovered-info').click();
// });

document.getElementById('close_code').addEventListener('click', function() {
    document.getElementById('confirm-button').click();
});

document.getElementById('close_recovered').addEventListener('click', function() {
    document.getElementById('confirm-recovered-info').click();
});