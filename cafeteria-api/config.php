<?php
// PHP Konfigurationsdatei für die Datenbankzugriffe

// BITTE PASSEN SIE DIESE WERTE AN IHRE MYSQL-UMGEBUNG AN!
// ----------------------------------------------------

define('DB_HOST', 'localhost');
define('DB_NAME', 'cafeteria_db'); // Der Name, den Sie in phpMyAdmin erstellt haben
define('DB_USER', 'root');   // Ihr Datenbank-Benutzername
define('DB_PASS', '');   // IHR DATENBANK-PASSWORT EINFÜGEN!

// Token-Konstanten
define('TOKEN_EXPIRY_DAYS', 7);
?>