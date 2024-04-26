document.addEventListener('DOMContentLoaded', function() {
    // Retrieve token from localStorage
    const token = localStorage.getItem('jwt_token');
    console.log('Token retrieved:', token); // Check if token is retrieved correctly

    const bookForm = document.getElementById('book-form');
    if (bookForm) {
        bookForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const title = document.getElementById('title').value;
            const author = document.getElementById('author').value;
            const genre = document.getElementById('genre').value;
            const bookId = document.getElementById('book-id').value;
            const mode = document.getElementById('form-mode').value;

            const endpoint = mode === 'new' ? '/books' : `/books/${bookId}`;
            const method = mode === 'new' ? 'POST' : 'PUT';

            fetch(endpoint, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}` // Include the token in the Authorization header
                },
                body: JSON.stringify({ title, author, genre }),
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                console.log(data);
                if (mode === 'new') {
                    loadBooks(); // Reload the list of books
                } else {
                    window.location.href = '/'; // Redirect to the main page
                }
                bookForm.reset(); // Reset the form after submission
            })
            .catch(error => console.error('Error:', error));
        });
    }

    function loadBooks() {
        const booksContainer = document.getElementById('books');
        if (booksContainer) {
            fetch('/books', {
                headers: {
                    'Authorization': `Bearer ${token}` // Ensure the token is sent with the request
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP status ${response.status}`);
                }
                return response.json();
            })
            .then(books => {
                booksContainer.innerHTML = '';
                books.forEach(book => {
                    const bookDiv = document.createElement('div');
                    bookDiv.innerHTML = `${book.title} by ${book.author} (${book.genre}) <button onclick="window.location.href='/books/${book.id}'">Edit</button> <button onclick="deleteBook(${book.id})">Delete</button>`;
                    booksContainer.appendChild(bookDiv);
                });
            })
            .catch(error => {
                console.error('Fetch error:', error);
            });
        }
    }

    function deleteBook(id) {
        fetch(`/books/${id}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}` // Include the token in the Authorization header
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP status ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log(data);
            loadBooks(); // Reload the list of books
        })
        .catch(error => console.error('Error:', error));
    }

    loadBooks(); // Initial load of books
});
