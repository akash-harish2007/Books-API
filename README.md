# 📚 Book API

A secure RESTful API for managing books with JWT authentication.

## Features
- User registration & login
- JWT-based authentication
- Password hashing with bcrypt
- Full CRUD operations
- MySQL database

## Tech Stack
- Node.js + Express
- MySQL
- JWT
- Bcrypt

## Installation
1. Clone the repo
2. Run `npm install`
3. Copy `.env.example` to `.env` and fill in values
4. Run `npm start`

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /register | Create new user |
| POST | /login | Login and get JWT |
| GET | /books | Get all books |
| GET | /books/:id | Get single book |
| POST | /books | Create book |
| PUT | /books/:id | Update book |
| PATCH | /books/:id | Partial update |
| DELETE | /books/:id | Delete book |