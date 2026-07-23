const express = require('express');
const app = express();
app.use(express.json());
const port = 8080;
const sql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Database
let conn = sql.createConnection({
    host: process.env.DB_HOST,

    user: process.env.DB_USER,

    password: process.env.DB_PASSWORD,

    database: process.env.DB_NAME
});

conn.connect((err) => {

    if (err) {

        console.log(err);

    }
    else {

        console.log("Database connected");

    }

});

app.get('/', (req, res) => {
    res.json({
        message: 'Welcome to the Book API!',
        endpoints: {
            'GET /books': 'Get all books',
            'GET /books/:id': 'Get book by ID',
            'POST /books': 'Create new book',
            'PUT /books/:id': 'Update entire book',
            'PATCH /books/:id': 'Partially update book',
            'DELETE /books/:id': 'Delete book'
        }
    });
});

// ============================================
// LOGIN - Verify credentials with bcrypt, then generate JWT
// ============================================
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                message: "Username and password required"
            });
        }

        const query = "SELECT * FROM users WHERE username = ?";
        conn.query(query, [username], async (result) => {
            try {

                if (result.length === 0) {
                    return res.status(401).json({
                        message: "Invalid credentials"
                    });
                }

                const user = result[0];

                const match = await bcrypt.compare(password, user.password);

                if (!match) {
                    return res.status(401).json({
                        message: "Invalid credentials"
                    });
                }

                // Generate JWT token
                if (!process.env.JWT_SECRET) {

                    throw new Error(
                        "JWT_SECRET missing"
                    );

                }

                const token = jwt.sign(
                    {
                        userId: user.id,
                        username: user.username,
                        email: user.email,
                        role: user.role || 'user'
                    },
                    process.env.JWT_SECRET,
                    { expiresIn: '1h' }
                );


                res.json({
                    message: "Login successful",
                    token: token,
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email
                    }
                });

            } catch (err) {
                console.error('Login error:', err);
                res.status(500).json({
                    message: "Login failed",
                    error: err.message
                });
            }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({
            message: "Login failed"
        });
    }
});

// ============================================
// REGISTER - Hash password with bcrypt before saving
// ============================================
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }

        const checkQuery = "SELECT * FROM users WHERE username = ? OR email = ?";
        conn.query(checkQuery, [username, email], async (err, result) => {
            try {
                if (err) throw err;

                if (result.length > 0) {
                    return res.status(409).json({
                        message: "Username or email already exists"
                    });
                }

                const hashedPassword = await bcrypt.hash(password, 10);

                const insertQuery = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
                conn.query(insertQuery, [username, email, hashedPassword], (err, result) => {
                    try {
                        if (err) throw err;

                        res.status(201).json({
                            message: "User registered successfully",
                            userId: result.insertId
                        });

                    } catch (err) {
                        console.error('Database error:', err);
                        res.status(500).json({
                            message: "Registration failed"
                        });
                    }
                });

            } catch (err) {
                console.error('Check error:', err);
                res.status(500).json({
                    message: "Registration failed"
                });
            }
        });

    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({
            message: "Registration failed"
        });
    }
});

// ============================================
// AUTHENTICATE TOKEN - Verify JWT 
// ============================================
async function authenticateToken(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({
                message: "No token provided"
            });
        }

        const token = authHeader.split(" ")[1];

        if (!token) {
            return res.status(401).json({
                message: "No token provided"
            });
        }

        try {
            const decoded = jwt.verify(
                token,
                process.env.JWT_SECRET
            );

            req.user = decoded;
            next();
        } catch (err) {
            return res.status(403).json({
                message: "Invalid or expired token"
            });
        }
    } catch (err) {
        return res.status(500).json({
            message: "Authentication error"
        });
    }
}

// ============================================
// GET all books
// ============================================
app.get('/books', authenticateToken, async (req, res) => {
    try {
        conn.query("SELECT * FROM books", function (err, result) {
            try {
                if (err) {
                    throw err;
                }
                res.json({
                    message: "Books retrieved successfully",
                    user: req.user,
                    books: result
                });
            } catch (err) {
                console.error('Database error:', err);
                res.status(500).json({
                    message: "Database Error",
                    error: err.message
                });
            }
        });
    } catch (err) {
        console.error('Database error:', err);
        res.status(500).json({
            message: "Database Error",
            error: err.message
        });
    }
});

// ============================================
// GET single book by ID
// ============================================
app.get('/books/:id', authenticateToken, (req, res) => {
    try {
        const id = parseInt(req.params.id);

        const query = "SELECT * FROM books WHERE id = ?";

        conn.query(query, [id], function (err, result) {  
            try {
                if (err) {
                    throw err;
                }
                if (result.length === 0) {
                    return res.status(404).json({
                        message: "Book not found"
                    });
                }
                res.status(200).json({
                    message: "Book retrieved successfully",
                    user: req.user,
                    book: result[0]
                });
            } catch (err) {
                return res.status(404).json({
                    message: "Book not found"
                });
            }
        });
    } catch (err) {
        return res.status(404).json({
            message: "Book not found"
        });
    }
});

// ============================================
// POST create new book
// ============================================
app.post('/books', authenticateToken, (req, res) => {
    try {
        const { title, author, year } = req.body;

        
        if (!title) {
            return res.status(400).json({
                message: "Title is required"
            });
        }

        if (!author) {
            return res.status(400).json({
                message: "Author is required"
            });
        }

        if (!year) {
            return res.status(400).json({
                message: "Year is required"
            });
        }

        if (typeof year !== 'number') {
            return res.status(400).json({
                message: "Year must be a number"
            });
        }

        const query = "INSERT INTO books (title, author, year) VALUES (?, ?, ?)";

        conn.query(query, [title, author, year], function (err, result) {
            try {
                if (err) {
                    throw err;
                }
                return res.status(201).json({
                    message: "Book created successfully",
                    bookId: result.insertId,
                    user: req.user
                });
            } catch (err) {
                console.log('Database error:', err);
                return res.status(500).json({
                    message: "Database error"
                });
            }
        });
    } catch (err) {
        console.log('Error:', err);
        return res.status(500).json({
            message: "Database error"
        });
    }
});

// ============================================
// PUT update entire book
// ============================================
app.put('/books/:id', authenticateToken, (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const { title, author, year } = req.body;

        if (!title || !author) {
            return res.status(400).json({
                message: "Title and author are required"
            });
        }

        if (year !== undefined && typeof year !== 'number') {
            return res.status(400).json({
                message: "Year must be a number"
            });
        }

        const query = "UPDATE books SET title = ?, author = ?, year = ? WHERE id = ?";

        conn.query(query, [title, author, year, id], function (err, result) {
            try {
                if (err) {
                    throw err;
                }
                if (result.affectedRows === 0) {
                    return res.status(404).json({
                        message: "Book not found"
                    });
                }
                res.status(200).json({
                    message: "Book updated successfully",
                    user: req.user
                });
            } catch (err) {
                console.log('Database error:', err);
                return res.status(500).json({
                    message: "Database error"
                });
            }
        });
    } catch (err) {
        console.log('Error:', err);
        return res.status(500).json({
            message: "Database error"
        });
    }
});

// ============================================
// PATCH partially update book
// ============================================
app.patch('/books/:id', authenticateToken, (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const { title, author, year } = req.body;

        // Build dynamic query for partial updates
        let updates = [];
        let values = [];

        if (title) {
            updates.push("title = ?");
            values.push(title);
        }
        if (author) {
            updates.push("author = ?");
            values.push(author);
        }
        if (year) {
            if (typeof year !== 'number') {
                return res.status(400).json({
                    message: "Year must be a number"
                });
            }
            updates.push("year = ?");
            values.push(year);
        }

        if (updates.length === 0) {
            return res.status(400).json({
                message: "At least one field to update is required"
            });
        }

        values.push(id);
        const query = `UPDATE books SET ${updates.join(', ')} WHERE id = ?`;

        conn.query(query, values, function (err, result) {
            try {
                if (err) {
                    throw err;
                }
                if (result.affectedRows === 0) {
                    return res.status(404).json({
                        message: "Book not found"
                    });
                }
                res.status(200).json({
                    message: "Book updated successfully",
                    user: req.user
                });
            } catch (err) {
                console.log('Database error:', err);
                return res.status(500).json({
                    message: "Database error"
                });
            }
        });
    } catch (err) {
        console.log('Error:', err);
        return res.status(500).json({
            message: "Database error"
        });
    }
});

// ============================================
// DELETE book
// ============================================
app.delete('/books/:id', authenticateToken, (req, res) => {
    try {
        const id = parseInt(req.params.id);

        const query = "DELETE FROM books WHERE id = ?";

        conn.query(query, [id], function (err, result) {
            try {
                if (err) {
                    throw err;
                }
                if (result.affectedRows === 0) {
                    return res.status(404).json({
                        message: "Book not found"
                    });
                }
                res.status(200).json({
                    message: "Book deleted successfully",
                    user: req.user
                });
            } catch (err) {
                console.log('Database error:', err);
                return res.status(500).json({
                    message: "Database error"
                });
            }
        });
    } catch (err) {
        console.log('Error:', err);
        return res.status(500).json({
            message: "Database error"
        });
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:8080`);
    console.log('\n📚 Book API Endpoints:');
    console.log('  GET    /books        - Get all books');
    console.log('  GET    /books/:id    - Get book by ID');
    console.log('  POST   /books        - Create new book');
    console.log('  PUT    /books/:id    - Update entire book');
    console.log('  PATCH  /books/:id    - Partially update book');
    console.log('  DELETE /books/:id    - Delete book');
});