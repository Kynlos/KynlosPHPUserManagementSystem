# PHP User Management System

This is a PHP-based user management system that allows for user registration, login, profile management, password reset, role-based access control (RBAC), and integration with GitHub OAuth for login. The system is designed to provide a secure and flexible solution for managing users and their permissions within a web application.

## Features

- User registration: Users can sign up for an account with a unique username, email, and password.
- User login: Registered users can securely log in to their accounts using their username and password.
- Profile management: Users can view and update their profile information, including their username, email, first name, last name, and avatar.
- Password reset: Users can request a password reset if they forget their password. A password reset link will be sent to their email.
- Role-based access control (RBAC): Administrators can assign different roles to users, granting them specific permissions within the system.
- GitHub OAuth integration: Users can log in to the system using their GitHub account, providing a seamless authentication experience.

## Setup

1. Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/php-user-management.git
```

2. Install dependencies using Composer:

```bash
php -S localhost:8000
```

## Accessing the Application

You can access the application in your web browser by navigating to:

[http://localhost:8000](http://localhost:8000)

## Usage

To use the application:

1. Register a new account by clicking on the "Register" link.
2. Log in to your account using your username and password.
3. Update your profile information on the "Profile" page.
4. Request a password reset if you forget your password.
5. Administrators can access the admin panel to manage users and their roles.
6. Users can log in using their GitHub account by clicking on the "Login with GitHub" button.

## Dependencies

This project relies on the following dependencies:

- [PHPMailer](https://github.com/PHPMailer/PHPMailer): Library for sending emails via SMTP.
- [RobThree/Authenticator](https://github.com/RobThree/TwoFactorAuth): Library for implementing two-factor authentication (2FA).

## Contributing

Contributions are welcome! If you find any bugs or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
