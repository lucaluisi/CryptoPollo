<?php
include('cryptopollo.php');

[$result, $message, $iv, $key, $error] = '';
$rounds = 10;

try {
    if (isset($_POST['encrypt'])) {
        $message = $_POST['message'];
        $iv = $_POST['iv'];
        $key = $_POST['key'];
        $rounds = (int) $_POST['rounds'];
        $cipher = new CryptoPollo(hex2bin($key), hex2bin($iv), (int) $rounds);
        $ciphertext = bin2hex($cipher->encrypt($message));
        $result = substr($ciphertext, 32);
    } elseif (isset($_POST['decrypt'])) {
        $message = $_POST['message'];
        $iv = $_POST['iv'];
        $key = $_POST['key'];
        $rounds = (int) $_POST['rounds'];
        $cipher = new CryptoPollo(hex2bin($key), hex2bin($iv), (int) $rounds);
        $decryptedMessage = $cipher->decrypt(hex2bin($iv . $message));
        if (strlen($decryptedMessage) === 0 && strlen($message) > 0) {
            throw new Exception('Error decrypting message.');
        }
        $result = $decryptedMessage;
    }
} catch (Exception $e) {
    $error = $e->getMessage();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CryptoPollo 🐔</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            font-family: Arial, sans-serif;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #f0f0f0;
        }
        main {
            background: white;
            padding: 30px;
            border-radius: 20px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 600px;
        }
        h1 {
            text-align: center;
            color: #333;
            font-size: 4rem;
        }
        input, textarea, button {
            width: 100%;
            margin: 15px 0;
            padding: 20px;
            border: 2px solid #ccc;
            border-radius: 10px;
            font-size: 24px;
        }
        button {
            background-color: #ffac33;
            color: white;
            border: none;
            cursor: pointer;
            flex: 0 0 30px;
        }
        button:hover {
            background-color: #f4900c;
        }
        .flex {
            display: flex;
            gap: 5px;
            align-items: center;
        }
        #error {
            color: red;
            text-align: center;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <main>
        <h1>CryptoPollo 🐔</h1>

        <form action="" method="post">
            <label for="message">Message</label>
            <textarea id="message" name="message" placeholder="Enter your message (hex if decrypt)" required><?= $message ?></textarea>
            
            <label for="key">Key (hex)</label>
            <span class="flex">
                <input type="text" id="key" name="key" placeholder="Enter your key (hex)" value="<?= $key ?>" required>
                <button type="button" onclick="generateKey()">Generate</button>
            </span>

            <label for="iv">IV (hex)</label>
            <span class="flex">
                <input type="text" id="iv" name="iv" placeholder="Enter your IV (hex)" value="<?= $iv ?>" required>
                <button type="button" onclick="generateIV()">Generate</button>
            </span>

            <label for="rounds">Rounds</label>
            <input type="number" name="rounds" placeholder="Enter number of rounds" value="<?= $rounds ?>" required>

            <button type="submit" name="encrypt">Encrypt</button>
            <button type="submit" name="decrypt">Decrypt</button>

            <textarea id="result" placeholder="Result" readonly><?= $result ?></textarea>
        </form>
    </main>
    <div id="error"><?= $error ?></div>
    <script>
        function generateKey() {
            document.getElementById('key').value = generateHex(16);
        }

        function generateIV() {
            document.getElementById('iv').value = generateHex(16);
        }

        function generateHex(length) {
            const array = new Uint8Array(length);
            crypto.getRandomValues(array);
            return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        }
    </script>
</body>
</html>