  const registerForm = document.getElementById("registerForm");
  const loginForm = document.getElementById("loginForm");
  const logoutButton = document.getElementById("logoutButton");
  const loadDashboardButton = document.getElementById('loadDataButton');

  if (registerForm) {
    registerForm.addEventListener("submit", (event) => {register(event)});
  }

  if (loginForm) {
    loginForm.addEventListener("submit", (event) => {login(event)});
  }

  if (logoutButton) {
    logoutButton.addEventListener("click", logout);
  }

  if (loadDashboardButton) {
    loadDashboardButton.addEventListener("click", loadUser);
  }

async function register(event) {
    event.preventDefault();
    const username = document.getElementById('usernameInput').value;
    const password = document.getElementById('passwordInput').value;

    const response = await fetch(
        'http://localhost:3000/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                password
            })
        }
    );

    const text = await response.text();
    if (!response.ok) {
        alert(text);
        return;
    }

    window.location.replace('login.html')
}

async function login (event) {
    event.preventDefault();
    const username = document.getElementById('usernameInput').value;
    const password = document.getElementById('passwordInput').value;

    const response = await fetch("http://localhost:3000/login", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        credentials: 'include',
        // credentials: include tells the program to include cookies. We use cookies to track access tokens.
        body: JSON.stringify({username,password})
    });

    event.target.reset();
    const text = await response.text();

    if(!response.ok) {
        alert(text);
        return;
    }

    window.location.replace('/dashboard');
}

async function loadUser() {
    const res = await fetch('/api/user', {
        credentials: 'include'
    });

    if (!res.ok) {
        window.location.replace('/login.html');
        return;
    }
    
    const data = await res.json();
    const username = data?.username || "User";

    document.getElementById('result').innerText = 
        `Welcome ${username}`;
}

async function logout() {
    await fetch('/logout', {
        method: 'POST',
        credentials: 'include'
    });

    window.location.replace('/login.html');
}