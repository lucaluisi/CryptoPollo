<?php

include('cryptopollo.php');

$key = random_bytes(16);
$iv = random_bytes(16);

$plaintext = "Chi sospetterebbe di un pollo crittografico 🐔?";
echo "Plaintext: " . $plaintext . "<br><br>";

$cipher = new CryptoPollo($key, $iv);

$ciphertext = $cipher->encrypt($plaintext);
echo "Ciphertext (hex): " . bin2hex($ciphertext) . "<br><br>";

$decryptedMessage = $cipher->decrypt($ciphertext);
echo "Decrypted: " . $decryptedMessage . "<br>";

?>