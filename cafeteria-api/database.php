<?php
require_once 'config.php';

/**
 * Stellt eine PDO-Datenbankverbindung her.
 * @return PDO
 */
function getDbConnection() {
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];

    try {
        // Versucht, die Verbindung zur Datenbank herzustellen
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        return $pdo;
    } catch (\PDOException $e) {
        // Im Fehlerfall (falsche Zugangsdaten) wird ein 500er Fehler gesendet
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Datenbankverbindungsfehler: ' . $e->getMessage()]);
        exit;
    }
}
?>