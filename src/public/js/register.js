const form = document.getElementById('registerForm');

form.addEventListener('submit', e => {
    e.preventDefault();
    const data = new FormData(form);
    const obj = {};
    data.forEach((value, key) => obj[key] = value);
    fetch('/api/sessions/register', {
        method: 'POST',
        body: JSON.stringify(obj),
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(response => {
            if (response.status === 200) {
                return response.json();
            } else {
                return response.json().then(data => {
                    if (data.error) {
                        alert(data.error);
                        window.location.href = '/register';
                    } else {
                        console.error('User registration error');
                    }
                });
            }
        })
        .then(data => {
            if (data.status === "success") {
                alert("Successfully registered user");
                window.location.href = '/login';
            }
        })
        .catch(error => {
            console.error('Request error:', error);
        });
});
