<?php
require_once 'database.php';

// Erlaubt CORS-Anfragen (anpassen für Produktionsumgebung!)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Content-Type: application/json');

// --- Preflight OPTIONS Request abfangen (für CORS) ---
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}
// ---------------------------------------------------

// POST/PUT-Daten als PHP-Array auslesen
$data = json_decode(file_get_contents('php://input'), true);
$method = $_SERVER['REQUEST_METHOD'];

// NEUE LOGIK: Route direkt aus dem Query-Parameter lesen
// Dies ist robuster, da wir im Client die Route als "?route=..." übergeben.
$route = $_GET['route'] ?? ''; 


// --- HELPER FUNCTIONS (Rest unverändert) ---
// ... (Die Helper-Funktionen bleiben gleich)

/**
 * Generiert einen sicheren Token (Session-Ersatz).
 */
function generateSecureToken() {
    return bin2hex(random_bytes(32)); // 64 Zeichen Hex-String
}

/**
 * Überprüft den Authorization-Header und gibt die Benutzerdaten zurück,
 * wenn der Token gültig ist.
 */
function authenticateUser($pdo) {
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? null;

    if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        return null;
    }

    $token = $matches[1];

    // Prüfen, ob der Token in der Datenbank existiert
    $stmt = $pdo->prepare("SELECT id, username, is_admin FROM users WHERE session_token = ?");
    $stmt->execute([$token]);
    $user = $stmt->fetch();

    return $user ?: null;
}

/**
 * Überprüft, ob der authentifizierte Benutzer Admin-Rechte hat.
 */
function requireAdmin($user) {
    if (!$user || !$user['is_admin']) {
        http_response_code(403);
        echo json_encode(['error' => 'Adminrechte erforderlich']);
        exit;
    }
}

/**
 * Generiert den 512-Bit Bestellcode
 */
function generateOrderCode() {
    return bin2hex(random_bytes(64)); // 128 Zeichen Hex-String
}

/**
 * Einfache Passwort-Validierung.
 */
function validatePassword($password) {
    // Min. 8 Zeichen, 1 Zahl, 1 Großbuchstaben, 1 Sonderzeichen
    return preg_match('/^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/', $password);
}


// --- API ROUTING ---

$pdo = getDbConnection(); // Stellt die Datenbankverbindung her

// Registrierung: POST /api_handler.php?route=register
if ($method === 'POST' && $route === 'register') {
    if (empty($data['username']) || empty($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Benutzername und Passwort erforderlich']);
        exit;
    }

    $username = $data['username'];
    $password = $data['password'];

    if (!validatePassword($password)) {
        http_response_code(400);
        echo json_encode(['error' => 'Passwort muss min. 8 Zeichen, 1 Zahl, 1 Großbuchstaben und 1 Sonderzeichen enthalten']);
        exit;
    }

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
    // Wenn 'admin' und die spezifische E-Mail enthalten sind, wird der Benutzer zum Admin
    $isAdmin = (strpos($username, 'admin') !== false && strpos($username, '@randommail.com') !== false);

    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)");
        $stmt->execute([$username, $passwordHash, $isAdmin]);
        http_response_code(201);
        echo json_encode(['message' => 'Benutzer erfolgreich registriert']);
    } catch (\PDOException $e) {
        if ($e->getCode() == '23000') { // 23000 ist der Code für UNIQUE constraint violation
            http_response_code(400);
            echo json_encode(['error' => 'Benutzername bereits vergeben']);
        } else {
            http_response_code(500);
            error_log("Registrierungsfehler: " . $e->getMessage());
            echo json_encode(['error' => 'Interner Serverfehler bei Registrierung']);
        }
    }
    exit;
}

// Login: POST /api_handler.php?route=login
if ($method === 'POST' && $route === 'login') {
    if (empty($data['username']) || empty($data['password'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Benutzername und Passwort erforderlich']);
        exit;
    }

    $username = $data['username'];
    $password = $data['password'];

    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, $user['password_hash'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Ungültige Anmeldedaten']);
        exit;
    }

    // Token generieren und in DB speichern
    $token = generateSecureToken();
    $stmt = $pdo->prepare("UPDATE users SET session_token = ? WHERE id = ?");
    $stmt->execute([$token, $user['id']]);

    // Token wird als Access und Refresh Token verwendet (simuliert JWT-Paar)
    echo json_encode(['accessToken' => $token, 'refreshToken' => $token]);
    exit;
}

// Bestellung erstellen: POST /api_handler.php?route=bestellung
if ($method === 'POST' && $route === 'bestellung') {
    $user = authenticateUser($pdo);
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Authentifizierung erforderlich']);
        exit;
    }
    
    $gericht = $data['gericht'] ?? null;
    $menge = $data['menge'] ?? null;
    $getraenk = $data['getraenk'] ?? 'Keines';
    $bemerkung = $data['bemerkung'] ?? '';

    if (empty($gericht) || empty($menge) || !is_numeric($menge) || $menge < 1) {
        http_response_code(400);
        echo json_encode(['error' => 'Gericht und Menge (>0) sind erforderlich.']);
        exit;
    }

    $orderCode = generateOrderCode();

    try {
        $stmt = $pdo->prepare(
            "INSERT INTO orders (user_id, dish, quantity, drink, notes, order_code) 
             VALUES (?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([$user['id'], $gericht, $menge, $getraenk, $bemerkung, $orderCode]);

        http_response_code(201);
        echo json_encode([
            'message' => 'Bestellung erfolgreich erstellt',
            'orderCode' => $orderCode
        ]);
    } catch (\PDOException $e) {
        http_response_code(500);
        error_log("Order error: " . $e->getMessage());
        echo json_encode(['error' => 'Interner Serverfehler bei Bestellung']);
    }
    exit;
}

// Bestellungen abrufen (Admin): GET /api_handler.php?route=bestellungen
if ($method === 'GET' && $route === 'bestellungen') {
    $user = authenticateUser($pdo);
    requireAdmin($user);

    try {
        $stmt = $pdo->query("SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC");
        $orders = $stmt->fetchAll();
        echo json_encode($orders);
    } catch (\PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Interner Serverfehler beim Abrufen der Bestellungen']);
    }
    exit;
}

// Status aktualisieren (Admin): PUT /api_handler.php?route=bestellung&id={id}
if ($method === 'PUT' && $route === 'bestellung' && isset($_GET['id'])) {
    $user = authenticateUser($pdo);
    requireAdmin($user);

    $orderId = $_GET['id'];
    $status = $data['status'] ?? null;

    if (!in_array($status, ['pending', 'abgeholt'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Ungültiger Status. Erlaubt: pending oder abgeholt']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("UPDATE orders SET status = ? WHERE id = ?");
        $stmt->execute([$status, $orderId]);

        if ($stmt->rowCount() == 0) {
            http_response_code(404);
            echo json_encode(['error' => 'Bestellung nicht gefunden']);
            exit;
        }

        http_response_code(200);
        echo json_encode(['message' => 'Status aktualisiert']);
    } catch (\PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Interner Serverfehler beim Status-Update']);
    }
    exit;
}

// PUT /api_handler.php?route=complete_order
if ($method === 'PUT' && $route === 'complete_order') {
    $user = authenticateUser($pdo);
    requireAdmin($user); // Nur Admins dürfen per Code abschließen

    $orderCode = $data['orderCode'] ?? null;
    
    // Prüfen des Codes (muss 128 Zeichen lang sein)
    if (empty($orderCode) || strlen($orderCode) !== 128) {
        http_response_code(400);
        echo json_encode(['error' => 'Ungültiger Bestellcode (muss 128 Zeichen lang sein)']);
        exit;
    }

    try {
        $stmt = $pdo->prepare("SELECT id, status FROM orders WHERE order_code = ?");
        $stmt->execute([$orderCode]);
        $order = $stmt->fetch();

        if (!$order) {
            http_response_code(404);
            echo json_encode(['error' => 'Bestellung mit diesem Code nicht gefunden']);
            exit;
        }
        if ($order['status'] === 'abgeholt') {
            http_response_code(400);
            echo json_encode(['error' => 'Diese Bestellung wurde bereits abgeholt']);
            exit;
        }

        $stmt = $pdo->prepare("UPDATE orders SET status = 'abgeholt' WHERE id = ?");
        $stmt->execute([$order['id']]);

        http_response_code(200);
        echo json_encode(['message' => 'Bestellung erfolgreich abgeschlossen']);

    } catch (\PDOException $e) {
        http_response_code(500);
        error_log("Code-Abschluss Fehler: " . $e->getMessage());
        echo json_encode(['error' => 'Interner Serverfehler beim Abschließen der Bestellung']);
    }
    exit;
}

// Fallback für nicht gefundene Routen oder Methoden
http_response_code(404);
echo json_encode(['error' => 'Endpunkt nicht gefunden oder Methode nicht erlaubt']);
?>