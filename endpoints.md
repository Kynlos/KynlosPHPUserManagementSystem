# GET /api/users:

## Function: getUsers()
Description: Retrieve a list of all users.
Example:
`curl -X GET http://localhost:8000/api/users`
GET /api/users/{id}:

## Function: getUserById($id)
Description: Retrieve user details by ID.
Example:
`curl -X GET http://localhost:8000/api/users/123`
GET /api/dashboard:

## Function: getDashboard()
Description: Retrieve dashboard data.
Example:
`curl -X GET http://localhost:8000/api/dashboard`
GET /api/admin:

## ## Function: getAdminPanel()
Description: Retrieve admin panel data (requires admin permissions).
Example:
`curl -X GET http://localhost:8000/api/admin`
POST /api/register:

## Function: registerUser()
Description: Register a new user.
Example:
`curl -X POST -H "Content-Type: application/json" -d '{"username": "example", "password": "password123", "email": "example@example.com"}' http://localhost:8000/api/register`
POST /api/login:

## Function: loginUser()
Description: Login with username and password.
Example:
`curl -X POST -H "Content-Type: application/json" -d '{"username": "example", "password": "password123"}' http://localhost:8000/api/login`
POST /api/github-login:

## Function: loginWithGitHub()
Description: Login with GitHub OAuth.
Example:
`curl -X POST http://localhost:8000/api/github-login?code=github_code_here`
POST /api/update-profile:

## Function: updateUserProfile()
Description: Update user profile.
Example:
`curl -X POST -H "Content-Type: application/json" -d '{"first_name": "John", "last_name": "Doe", "avatar": "avatar_url_here"}' http://localhost:8000/api/update-profile`
POST /api/request-password-reset:

## Function: requestPasswordReset()
Description: Request a password reset.
Example:
`curl -X POST -H "Content-Type: application/json" -d '{"email": "example@example.com"}' http://localhost:8000/api/request-password-reset`
POST /api/reset-password:

## Function: resetPassword()
Description: Reset user password.
Example:
`curl -X POST -H "Content-Type: application/json" -d '{"token": "reset_token_here", "password": "new_password_here"}' http://localhost:8000/api/reset-password`
POST /api/setup-2fa:

## Function: setup2FA()
Description: Set up two-factor authentication.
Example:
`curl -X POST http://localhost:8000/api/setup-2fa`
POST /api/invite-user:

## Function: inviteUser()
Description: Invite a new user (requires admin permissions).
Example:
`curl -X POST -H "Content-Type: application/json" -d '{"email": "new_user@example.com", "role": "user"}' http://localhost:8000/api/invite-user`
PUT /api/users/{id}:

## Function: updateUser($id)
Description: Update user information (requires admin permissions).
Example:
`curl -X PUT -H "Content-Type: application/json" -d '{"username": "new_username", "email": "new_email@example.com", "role": "admin"}' http://localhost:8000/api/users/123`
DELETE /api/users/{id}:

## Function: deleteUser($id)
Description: Delete a user (requires admin permissions).
Example:
`curl -X DELETE http://localhost:8000/api/users/123`
GET /login:

## Function: showLoginPage()
Description: Show login page.
Example:
`curl -X GET http://localhost:8000/login`
GET /register:

## Function: showRegistrationPage()
Description: Show registration page.
Example:
`curl -X GET http://localhost:8000/register`
GET /admin:

## Function: showAdminDashboard()
Description: Show admin dashboard page (requires admin permissions).
Example:
`curl -X GET http://localhost:8000/admin`
GET /forgot-password:

## Function: showForgotPasswordPage()
Description: Show forgot password page.
Example:
`curl -X GET http://localhost:8000/forgot-password`
GET /reset-password:

## Function: showResetPasswordPage()
Description: Show reset password page.
Example:
`curl -X GET http://localhost:8000/reset-password?token=reset_token_here`
GET /setup-2fa:

## Function: show2FASetupPage()
Description: Show two-factor authentication setup page.
Example:
`curl -X GET http://localhost:8000/setup-2fa`
GET /invite:

## Function: showInvitePage()
Description: Show invite user page (requires admin permissions).
Example:
`curl -X GET http://localhost:8000/invite`
GET /api-docs:

## Function: showAPIDocumentation()
Description: Show API documentation page.
Example:
`curl -X GET http://localhost:8000/api-docs`
GET /github-callback:

## Function: handleGitHubCallback()
Description: Handle GitHub OAuth callback.
Example:
`curl -X GET http://localhost:8000/github-callback`