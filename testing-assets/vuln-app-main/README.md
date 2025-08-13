# Vulnerable Web Application

This is a deliberately vulnerable web application designed for security testing and educational purposes. It contains several common web vulnerabilities that can be exploited to demonstrate security issues.

## Vulnerabilities

1. **SQL Injection**
   - Location: Login form and search functionality
   - Example: `' OR '1'='1` in the username field

2. **Stored XSS (Cross-Site Scripting)**
   - Location: Comments section
   - Example: `<script>alert('XSS')</script>` in a comment

3. **SSRF (Server-Side Request Forgery)**
   - Location: API endpoint `/api/fetch?url=`
   - Example: `/api/fetch?url=http://internal-service`

4. **IDOR (Insecure Direct Object Reference)**
   - Location: Document access and user management
   - Example: Accessing `/profile/2` without proper authorization

5. **Path Traversal**
   - Location: File upload and download functionality
   - Example: Uploading a file with a path like `../../../etc/passwd`

## Setup

1. Install Docker and Docker Compose if you haven't already.

2. Build and start the containers:
   ```bash
   docker-compose up --build
   ```

3. The application will be available at `http://localhost:5000`

## Default Credentials

- Admin: `admin` / `admin123`
- User: `user1` / `user123`

## API Access

The API is available under the `/api` endpoint. Use the following API key for testing:

```
api_key=insecure_api_key_123
```

## Security Note

⚠️ **WARNING**: This application is intentionally vulnerable and should NEVER be deployed in a production environment or exposed to the internet. It is for educational purposes only.

## License

This project is for educational use only. Use it responsibly and only on systems you have permission to test.
