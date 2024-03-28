<?php

// Database connection
$db = new SQLite3('database.db');

// Create tables if they don't exist
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    first_name TEXT,
    last_name TEXT,
    avatar TEXT,
    is_admin INTEGER DEFAULT 0,
    github_id TEXT UNIQUE,
    2fa_secret TEXT,
    role_id INTEGER,
    FOREIGN KEY (role_id) REFERENCES roles(id)
)");

$db->exec("CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
)");

$db->exec("CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
)");

$db->exec("CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
)");

$db->exec("CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)");

$db->exec("CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expiration DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
)");

// Insert default roles and permissions if they don't exist
$db->exec("INSERT OR IGNORE INTO roles (name) VALUES ('admin'), ('moderator'), ('user')");
$db->exec("INSERT OR IGNORE INTO permissions (name) VALUES
    ('create_post'), ('edit_post'), ('delete_post'), ('manage_users'), ('manage_roles')
");

$db->exec("INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
    SELECT (SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'create_post')
    UNION ALL
    SELECT (SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'edit_post')
    UNION ALL
    SELECT (SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'delete_post')
    UNION ALL
    SELECT (SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'manage_users')
    UNION ALL
    SELECT (SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'manage_roles')
    UNION ALL
    SELECT (SELECT id FROM roles WHERE name = 'moderator'), (SELECT id FROM permissions WHERE name = 'create_post')
    UNION ALL
    SELECT (SELECT id FROM roles WHERE name = 'moderator'), (SELECT id FROM permissions WHERE name = 'edit_post')
    UNION ALL
    SELECT (SELECT id FROM roles WHERE name = 'moderator'), (SELECT id FROM permissions WHERE name = 'delete_post')
    UNION ALL
    SELECT (SELECT id FROM roles WHERE name = 'user'), (SELECT id FROM permissions WHERE name = 'create_post')
");

// Define the API routes and their corresponding functions
$routes = [
    'GET' => [
        '/api/users' => 'getUsers',
        '/api/users/(?<id>\d+)' => 'getUserById',
        '/api/dashboard' => 'getDashboard',
        '/api/admin' => 'getAdminPanel',
        '/api/profile' => 'getUserProfile',
        '/api/activity-logs' => 'getActivityLogs',
        '/login' => 'showLoginPage',
        '/register' => 'showRegistrationPage',
        '/admin' => 'showAdminDashboard',
        '/forgot-password' => 'showForgotPasswordPage',
        '/reset-password' => 'showResetPasswordPage',
        '/setup-2fa' => 'show2FASetupPage',
        '/invite' => 'showInvitePage',
        '/api-docs' => 'showAPIDocumentation',
        '/github-callback' => 'handleGitHubCallback'
    ],
    'POST' => [
        '/api/register' => 'registerUser',
        '/api/login' => 'loginUser',
        '/api/github-login' => 'loginWithGitHub',
        '/api/update-profile' => 'updateUserProfile',
        '/api/request-password-reset' => 'requestPasswordReset',
        '/api/reset-password' => 'resetPassword',
        '/api/setup-2fa' => 'setup2FA',
        '/api/invite-user' => 'inviteUser'
    ],
    'PUT' => [
        '/api/users/(?<id>\d+)' => 'updateUser'
    ],
    'DELETE' => [
        '/api/users/(?<id>\d+)' => 'deleteUser'
    ]
];

// GitHub OAuth configuration
$githubClientId = getenv('GITHUB_CLIENT_ID');
$githubClientSecret = getenv('GITHUB_CLIENT_SECRET');

// User authentication
session_start();

// Helper functions
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    global $db;
    $userId = $_SESSION['user_id'];
    $stmt = $db->prepare("SELECT r.name AS role_name
                          FROM users u
                          JOIN roles r ON u.role_id = r.id
                          WHERE u.id = :userId");
    $stmt->bindValue(':userId', $userId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row['role_name'] == 'admin';
}

function hasPermission($permissionName) {
    global $db;
    $userId = $_SESSION['user_id'];
    $stmt = $db->prepare("SELECT EXISTS(
                            SELECT 1
                            FROM role_permissions rp
                            JOIN permissions p ON rp.permission_id = p.id
                            JOIN roles r ON rp.role_id = r.id
                            JOIN users u ON u.role_id = r.id
                            WHERE u.id = :userId AND p.name = :permissionName
                          )");
    $stmt->bindValue(':userId', $userId, SQLITE3_INTEGER);
    $stmt->bindValue(':permissionName', $permissionName, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_NUM);
    return $row[0] == 1;
}

function logActivity($action) {
    global $db;
    $userId = $_SESSION['user_id'];
    $stmt = $db->prepare("INSERT INTO activity_logs (user_id, action) VALUES (:userId, :action)");
    $stmt->bindValue(':userId', $userId, SQLITE3_INTEGER);
    $stmt->bindValue(':action', $action, SQLITE3_TEXT);
    $stmt->execute();
}

// API functions
function getUsers() {
    if (!hasPermission('manage_users')) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    global $db;
    $stmt = $db->prepare("SELECT id, username, email, first_name, last_name, avatar, r.name AS role_name
                          FROM users u
                          JOIN roles r ON u.role_id = r.id");
    $result = $stmt->execute();
    $users = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $users[] = $row;
    }
    header('Content-Type: application/json');
    echo json_encode($users);
}

function getUserById($id) {
    if (!hasPermission('manage_users')) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    global $db;
    $stmt = $db->prepare("SELECT id, username, email, first_name, last_name, avatar, r.name AS role_name
                          FROM users u
                          JOIN roles r ON u.role_id = r.id
                          WHERE u.id = :id");
    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    header('Content-Type: application/json');
    echo json_encode($row);
}

function registerUser($data) {
    global $db;
    $username = $data['username'];
    $password = password_hash($data['password'], PASSWORD_DEFAULT);
    $email = $data['email'];
    $roleId = (int) ($data['role_id'] ?: 3); // Default to 'user' role

    $stmt = $db->prepare("INSERT INTO users (username, password, email, role_id) VALUES (:username, :password, :email, :roleId)");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $password, SQLITE3_TEXT);
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    $stmt->bindValue(':roleId', $roleId, SQLITE3_INTEGER);
    $stmt->execute();
    logActivity('User registered');
    header('Content-Type: application/json');
    echo json_encode(['message' => 'User registered successfully']);
}

function loginUser() {
    global $db;
    $data = json_decode(file_get_contents('php://input'), true);
    $username = $data['username'];
    $stmt = $db->prepare("SELECT id, password, 2fa_secret FROM users WHERE username = :username");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    if ($row && password_verify($data['password'], $row['password'])) {
        if (!empty($row['2fa_secret'])) {
            // 2FA is enabled, verify the code
            $code = $data['code'];
            $secret = $row['2fa_secret'];
            $valid = verifyTOTP($secret, $code);
            if (!$valid) {
                header('HTTP/1.1 401 Unauthorized');
                echo json_encode(['error' => 'Invalid 2FA code']);
                return;
            }
        }
        $_SESSION['user_id'] = $row['id'];
        logActivity('User logged in');
        header('Content-Type: application/json');
        echo json_encode(['message' => 'Login successful']);
    } else {
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(['error' => 'Invalid username or password']);
    }
}

function loginWithGitHub() {
    $code = $_GET['code'];
    
    // Validate the code parameter
    if (empty($code) || !isValidAuthorizationCode($code)) {
        header('HTTP/1.1 400 Bad Request');
        echo json_encode(['error' => 'Invalid authorization code']);
        return;
    }

    global $githubClientId, $githubClientSecret;
    $accessToken = getGitHubAccessToken($code, $githubClientId, $githubClientSecret);
    $userInfo = getGitHubUserInfo($accessToken);

    global $db;
    $githubId = $userInfo->id;
    $stmt = $db->prepare("SELECT id FROM users WHERE github_id = :githubId");
    $stmt->bindValue(':githubId', $githubId, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        // User already exists, log them in
        $_SESSION['user_id'] = $row['id'];
        logActivity('User logged in with GitHub');
        header('Location: /dashboard');
    } else {
        // User doesn't exist, create a new account
        $username = $userInfo->login ?: 'github_' . $userInfo->id;
        $email = $userInfo->email ?: 'github_' . $userInfo->id . '@example.com';
        $stmt = $db->prepare("SELECT id FROM roles WHERE name = 'user'");
        $result = $stmt->execute();
        $roleId = $result->fetchArray(SQLITE3_NUM)[0];
        $stmt = $db->prepare("INSERT INTO users (username, email, github_id, role_id) VALUES (:username, :email, :githubId, :roleId)");
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $stmt->bindValue(':email', $email, SQLITE3_TEXT);
        $stmt->bindValue(':githubId', $githubId, SQLITE3_TEXT);
        $stmt->bindValue(':roleId', $roleId, SQLITE3_INTEGER);
        $stmt->execute();
        $userId = $db->lastInsertRowID();
        $_SESSION['user_id'] = $userId;
        logActivity('User registered with GitHub');
        header('Location: /dashboard');
    }
}

function getDashboard() {
    if (!isLoggedIn()) {
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    // Code to fetch dashboard data
    $dashboardData = ['message' => 'Welcome to the dashboard'];
    header('Content-Type: application/json');
    echo json_encode($dashboardData);
}

function getAdminPanel() {
    if (!isLoggedIn() || !isAdmin()) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Forbidden']);
        return;
    }
    // Code to fetch admin panel data
    $adminPanelData = ['message' => 'Welcome to the admin panel'];
    header('Content-Type: application/json');
    echo json_encode($adminPanelData);
}

function getUserProfile() {
    if (!isLoggedIn()) {
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    global $db;
    $userId = $_SESSION['user_id'];
    $stmt = $db->prepare("SELECT username, email, first_name, last_name, avatar
                          FROM users
                          WHERE id = :userId");
    $stmt->bindValue(':userId', $userId, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    header('Content-Type: application/json');
    echo json_encode($row);
}

function getActivityLogs() {
    if (!isLoggedIn() || !isAdmin()) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    global $db;
    $stmt = $db->prepare("SELECT al.id, u.username, al.action, al.timestamp
                          FROM activity_logs al
                          JOIN users u ON al.user_id = u.id
                          ORDER BY al.timestamp DESC");
    $result = $stmt->execute();
    $logs = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $logs[] = $row;
    }
    header('Content-Type: application/json');
    echo json_encode($logs);
}

function updateUserProfile() {
    if (!isLoggedIn()) {
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    global $db;
    $userId = $_SESSION['user_id'];
    $data = json_decode(file_get_contents('php://input'), true);
    $firstName = filter_var($data['first_name'], FILTER_SANITIZE_STRING);
    $lastName = filter_var($data['last_name'], FILTER_SANITIZE_STRING);
    $avatar = filter_var($data['avatar'], FILTER_SANITIZE_URL);

    $stmt = $db->prepare("UPDATE users
                          SET first_name = :firstName, last_name = :lastName, avatar = :avatar
                          WHERE id = :userId");
    $stmt->bindValue(':firstName', $firstName, SQLITE3_TEXT);
    $stmt->bindValue(':lastName', $lastName, SQLITE3_TEXT);
    $stmt->bindValue(':avatar', $avatar, SQLITE3_TEXT);
    $stmt->bindValue(':userId', $userId, SQLITE3_INTEGER);
    $stmt->execute();
    logActivity('User updated profile');
    header('Content-Type: application/json');
    echo json_encode(['message' => 'Profile updated successfully']);
}

function updateUser($id) {
    if (!isLoggedIn() || !hasPermission('manage_users')) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    global $db;
    $data = json_decode(file_get_contents('php://input'), true);
    $username = filter_var($data['username'], FILTER_SANITIZE_STRING);
    $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
    $stmt = $db->prepare("SELECT id FROM roles WHERE name = :roleName");
    $stmt->bindValue(':roleName', $data['role'], SQLITE3_TEXT);
    $result = $stmt->execute();
    $roleId = $result->fetchArray(SQLITE3_NUM)[0];

    $stmt = $db->prepare("UPDATE users
                          SET username = :username, email = :email, role_id = :roleId
                          WHERE id = :id");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    $stmt->bindValue(':roleId', $roleId, SQLITE3_INTEGER);
    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
    $stmt->execute();
    logActivity("User updated (ID: $id)");
    header('Content-Type: application/json');
    echo json_encode(['message' => 'User updated successfully']);
}

function deleteUser($id) {
    if (!isLoggedIn() || !hasPermission('manage_users')) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    global $db;
    $stmt = $db->prepare("DELETE FROM users WHERE id = :id");
    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
    $stmt->execute();
    logActivity("User deleted (ID: $id)");
    header('Content-Type: application/json');
    echo json_encode(['message' => 'User deleted successfully']);
}

function requestPasswordReset() {
    global $db;
    $data = json_decode(file_get_contents('php://input'), true);
    $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);

    $stmt = $db->prepare("SELECT id FROM users WHERE email = :email");
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if ($row) {
        $userId = $row['id'];
        $token = bin2hex(random_bytes(16));
        $expirationTime = new DateTime('+ 1 hour');

        $stmt = $db->prepare("INSERT INTO password_resets (user_id, token, expiration)
                              VALUES (:userId, :token, :expirationTime)");
        $stmt->bindValue(':userId', $userId, SQLITE3_INTEGER);
        $stmt->bindValue(':token', $token, SQLITE3_TEXT);
        $stmt->bindValue(':expirationTime', $expirationTime->format('Y-m-d H:i:s'), SQLITE3_TEXT);
        $stmt->execute();

        $resetLink = "http://{$_SERVER['HTTP_HOST']}/reset-password?token=" . urlencode($token);
        $resetLink = filter_var($resetLink, FILTER_SANITIZE_URL);
        sendPasswordResetEmail($email, $resetLink);

        header('Content-Type: application/json');
        echo json_encode(['message' => 'Password reset link sent to your email']);
    } else {
        header('HTTP/1.1 404 Not Found');
        echo json_encode(['error' => 'Email not found']);
    }
}


function resetPassword() {
    global $db;
    $data = json_decode(file_get_contents('php://input'), true);
    $token = filter_var($data['token'], FILTER_SANITIZE_STRING);

    // Validate the token parameter
    $stmt = $db->prepare("SELECT user_id, expiration
                          FROM password_resets
                          WHERE token = :token");
    $stmt->bindValue(':token', $token, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if (!$row) {
        header('HTTP/1.1 404 Not Found');
        echo json_encode(['error' => 'Invalid token']);
        return;
    }

    $userId = $row['user_id'];
    $expiration = new DateTime($row['expiration']);
    $now = new DateTime();

    if ($now > $expiration) {
        header('HTTP/1.1 400 Bad Request');
        echo json_encode(['error' => 'Token expired']);
        return;
    }

    if ($newPassword !== $confirmPassword) {
        header('HTTP/1.1 400 Bad Request');
        echo json_encode(['error' => 'Passwords do not match']);
        return;
    }

    $stmt = $db->prepare("UPDATE users
                              SET password = :newPassword
                              WHERE id = :userId");
    $stmt->bindValue(':newPassword', $newPassword, SQLITE3_TEXT);
    $stmt->bindValue(':userId', $userId, SQLITE3_INTEGER);
    $stmt->execute();

    $stmt = $db->prepare("DELETE FROM password_resets WHERE token = :token");
    $stmt->bindValue(':token', $token, SQLITE3_TEXT);
    $stmt->execute();

    logActivity("User reset password (ID: $userId)");
    header('Content-Type: application/json');
    echo json_encode(['message' => 'Password reset successful']);
}

function setup2FA() {
    if (!isLoggedIn()) {
        header('HTTP/1.1 401 Unauthorized');
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }

    global $db;
    $userId = $_SESSION['user_id'];
    $secret = generateTOTPSecret();

    $stmt = $db->prepare("UPDATE users
                          SET 2fa_secret = :secret
                          WHERE id = :userId");
    $stmt->bindValue(':secret', $secret, SQLITE3_TEXT);
    $stmt->bindValue(':userId', $userId, SQLITE3_INTEGER);
    $stmt->execute();

    $qrCodeUrl = getTOTPQRCodeURL('My App', $secret, $userId);

    logActivity("User set up 2FA (ID: $userId)");
    header('Content-Type: application/json');
    echo json_encode(['qrcode_url' => $qrCodeUrl, 'secret' => $secret]);
}

function inviteUser() {
    if (!isLoggedIn() || !hasPermission('manage_users')) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Forbidden']);
        return;
    }

    global $db;
    $data = json_decode(file_get_contents('php://input'), true);
    $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
    $stmt = $db->prepare("SELECT id FROM roles WHERE name = :roleName");
    $stmt->bindValue(':roleName', $data['role'], SQLITE3_TEXT);
    $result = $stmt->execute();
    $roleId = $result->fetchArray(SQLITE3_NUM)[0];
    $password = generateRandomPassword();
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $db->prepare("INSERT INTO users (email, password, role_id)
                          VALUES (:email, :password, :roleId)");
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    $stmt->bindValue(':password', $hashedPassword, SQLITE3_TEXT);
    $stmt->bindValue(':roleId', $roleId, SQLITE3_INTEGER);
    $stmt->execute();
    $userId = $db->lastInsertRowID();

    sendInvitationEmail($email, $password);

    logActivity("User invited (ID: $userId)");
    header('Content-Type: application/json');
    echo json_encode(['message' => 'User invited successfully']);
}

// GitHub OAuth functions
function getGitHubAccessToken($code, $clientId, $clientSecret) {
    $url = 'https://github.com/login/oauth/access_token';
    $data = [
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
        'code' => $code
    ];
    $options = [
        CURLOPT_URL => $url,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($data),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Accept: application/json']
    ];

    $curl = curl_init();
    curl_setopt_array($curl, $options);
    $response = curl_exec($curl);
    curl_close($curl);

    $jsonResponse = json_decode($response, true);
    if (isset($jsonResponse['access_token'])) {
        return $jsonResponse['access_token'];
    } else {
        return null;
    }
}

function getGitHubUserInfo($accessToken) {
    $url = 'https://api.github.com/user';
    $options = [
        CURLOPT_URL => $url,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $accessToken,
            'User-Agent: Your-App-Name'
        ],
        CURLOPT_RETURNTRANSFER => true
    ];

    $curl = curl_init();
    curl_setopt_array($curl, $options);
    $response = curl_exec($curl);
    curl_close($curl);

    return json_decode($response);
}

// Page rendering functions
function showLoginPage() {
    $githubLoginUrl = 'https://github.com/login/oauth/authorize?client_id=' . $GLOBALS['githubClientId'];
    include 'login.php';
}

function showRegistrationPage() {
    include 'register.php';
}

function showAdminDashboard() {
    if (!isLoggedIn() || !isAdmin()) {
        header('HTTP/1.1 403 Forbidden');
        echo 'Forbidden';
        return;
    }
    include 'admin.php';
}

function showForgotPasswordPage() {
    include 'forgot-password.php';
}

function showResetPasswordPage() {
    $token = filter_input(INPUT_GET, 'token', FILTER_SANITIZE_STRING);
    include 'reset-password.php';
}

function show2FASetupPage() {
    if (!isLoggedIn()) {
        header('HTTP/1.1 401 Unauthorized');
        echo 'Unauthorized';
        return;
    }
    include '2fa-setup.php';
}

function showInvitePage() {
    if (!isLoggedIn() || !hasPermission('manage_users')) {
        header('HTTP/1.1 403 Forbidden');
        echo 'Forbidden';
        return;
    }
    include 'invite.php';
}

function showAPIDocumentation() {
    include 'api-docs.php';
}

function handleGitHubCallback() {
    loginWithGitHub();
}

// Helper functions for 2FA, email, and other utilities
function generateTOTPSecret() {
    return bin2hex(random_bytes(16));
}

function verifyTOTP($secret, $code) {
    $ga = new \RobThree\Auth\TwoFactorAuth('My App');
    return $ga->verifyCode($secret, $code);
}

function getTOTPQRCodeURL($issuer, $secret, $userId) {
    $ga = new \RobThree\Auth\TwoFactorAuth($issuer);
    return $ga->getQRCodeGoogleUrl('My App User', $secret, $userId);
}

/*composer require phpmailer/phpmailer*/

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

function sendPasswordResetEmail($email, $resetLink) {
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host = getenv('SMTP_HOST');
        $mail->SMTPAuth = true;
        $mail->Username = getenv('SMTP_USERNAME');
        $mail->Password = getenv('SMTP_PASSWORD');
        $mail->SMTPSecure = 'tls';
        $mail->Port = getenv('SMTP_PORT');

        // Recipients
        $mail->setFrom(getenv('FROM_EMAIL'), getenv('FROM_NAME'));
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Password Reset';
        
        // Sanitize the reset link
        $resetLink = filter_var($resetLink, FILTER_SANITIZE_URL);
        
        // Build the email body
        $emailBody = 'Click the following link to reset your password: <a href="' . htmlspecialchars($resetLink, ENT_QUOTES, 'UTF-8') . '">Reset Password</a>';
        
        // Set the email body
        $mail->Body = $emailBody;

        $mail->send();
        return true;
    } catch (Exception $e) {
        return false;
    }
}



function sendInvitationEmail($email, $password) {
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host = getenv('SMTP_HOST');
        $mail->SMTPAuth = true;
        $mail->Username = getenv('SMTP_USERNAME');
        $mail->Password = getenv('SMTP_PASSWORD');
        $mail->SMTPSecure = 'tls';
        $mail->Port = getenv('SMTP_PORT');

        // Recipients
        $mail->setFrom(getenv('FROM_EMAIL'), getenv('FROM_NAME'));
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Invitation to Your App';
        $mail->Body    = 'Welcome! Your password is: ' . $password;

        $mail->send();
        return true;
    } catch (Exception $e) {
        return false;
    }
}

function generateRandomPassword($length = 12) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+';
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $password;
}

// Handle the incoming request
$method = $_SERVER['REQUEST_METHOD'];
$uri = $_SERVER['REQUEST_URI'];

foreach ($routes[$method] as $route => $function) {
    if (preg_match('#^' . $route . '$#', $uri, $matches)) {
        $params = array_slice($matches, 1);
        call_user_func_array($function, $params);
        exit();
    }
}

header('HTTP/1.1 404 Not Found');
echo json_encode(['error' => 'Page not found']);

?>