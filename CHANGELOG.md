## [1.2.1] - 2024-03-28

### Added

- Added support for two-factor authentication (2FA) using time-based one-time passwords (TOTP).
- Added functionality to invite new users to the application.
- Added GitHub OAuth integration for user registration and login.
- Added activity logging to track user actions.
- Added role-based access control (RBAC) system with permissions.

### Changed

- Refactored the database schema to support new features.
- Improved input validation and sanitization to prevent security vulnerabilities.
- Enhanced error handling and logging mechanisms.
- Instead of directly assigning the `$emailBody` to the Body property of the PHPMailer instance, we now use the `msgHTML()` method to set the email body.
- The `msgHTML()` method automatically handles the encoding of special characters and neutralizes any potentially malicious content within the email body.
- We no longer need to use `htmlspecialchars()` to encode the $resetLink because the `msgHTML()` method takes care of that for us.
- By using the `msgHTML()` method, we add an extra layer of protection against potential injection attacks through the email body. The method ensures that any special characters or potentially malicious content is properly encoded and neutralized before sending the email.

### Fixed

- The `updateUser` function now checks if the user exists before updating their information, preventing data corruption.
- The `deleteUser` function now checks if the user has any associated data in other tables, ensuring data consistency.
- The `requestPasswordReset` function now checks if the user already has a pending password reset request, preventing attackers from locking out users.
- The `resetPassword` function now checks if the password reset token is valid and has not expired, preventing unauthorized password resets.
- The `setup2FA` function now checks if the user already has 2FA enabled, preventing the user's 2FA secret from being overwritten.

### Refactored

- The `isLoggedIn` and `isAdmin` functions are now DRY (Don't Repeat Yourself). They use a single database query to check user permissions.
- The `hasPermission` function is now DRY. It uses the same database query as the `isAdmin` function.
- The `logActivity` function is now DRY. It uses a similar database query to the `updateUser` and `deleteUser` functions.
- The `getDashboard`, `getAdminPanel`, `getUserProfile`, and `getActivityLogs` functions now use similar database queries to retrieve user-related data.
- The `updateUserProfile`, `updateUser`, and `deleteUser` functions now use similar database queries to update or delete user information.
- The `requestPasswordReset`, `resetPassword`, and `setup2FA` functions now use similar database queries to manage user authentication and security.

### Security

- The password reset token is now stored as a hash in the database, enhancing security.
- The 2FA secret is now stored as a hash in the database, enhancing security.
- The `generateRandomPassword` function is now more secure and generates passwords with a length of 12 characters.
