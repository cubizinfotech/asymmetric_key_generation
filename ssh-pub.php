<?php

require 'vendor/autoload.php';

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\EC;

// Generate a unique file name for the key pair
$uniqueId = uniqid();
$privateKeyFile = __DIR__ . "/private_{$uniqueId}.pem";
$publicKeyFile = __DIR__ . "/public_{$uniqueId}.pem";

// Generate ED25519 key pair
function generateKeyPairED25519($privateKeyFile, $publicKeyFile) {
    
    $privateKey = EC::createKey('Ed25519');
    file_put_contents($privateKeyFile, $privateKey);

    $publicKey = $privateKey->getPublicKey();
    file_put_contents($publicKeyFile, $publicKey);

    return array('privateKey' => $privateKey, 'publicKey' => $publicKey);
}

// Generate RSA key pair
function generateKeyPair($privateKeyFile, $publicKeyFile) {
    
    $privateKey = RSA::createKey(4096);
    file_put_contents($privateKeyFile, $privateKey);

    $publicKey = $privateKey->getPublicKey();
    file_put_contents($publicKeyFile, $publicKey);

    return array('privateKey' => $privateKey, 'publicKey' => $publicKey);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    if ($_POST['action'] === 'generate_keys_ED25519') {
        $keyPair = generateKeyPairED25519($privateKeyFile, $publicKeyFile);
        echo json_encode(['private_key' => file_get_contents($privateKeyFile), 'public_key' => file_get_contents($publicKeyFile)]);
        unlink($privateKeyFile);
        unlink($publicKeyFile);
        exit;
    }

    if ($_POST['action'] === 'generate_keys') {
        $keyPair = generateKeyPair($privateKeyFile, $publicKeyFile);
        echo json_encode(['private_key' => file_get_contents($privateKeyFile), 'public_key' => file_get_contents($publicKeyFile)]);
        unlink($privateKeyFile);
        unlink($publicKeyFile);
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crypto Forms</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body class="container mt-3">
    <div class="card">
        <div class="card-header">
            <h3 class="card-title">Generating an ED25519 Public/Private keypair</h3>
        </div>
        <div class="card-body">
            <form id="keyFormED25519">
                <center><button type="submit" class="btn btn-primary">Generate Keys</button></center>
            </form>
        </div>
        <div class="card-footer">
            <div class="row">
                <div class="col-sm-6">
                    <label for="privateKey"><b>Private Key:</b></label>
                    <textarea id="privateKey-ED25519" class="form-control mt-2" rows="9" readonly></textarea>
                    <button class="btn btn-secondary mt-2 copy-btn" data-target="privateKey-ED25519">Copy Private Key</button>
                </div>
                <div class="col-sm-6">
                    <label for="publicKey"><b>Public Key:</b></label>
                    <textarea id="publicKey-ED25519" class="form-control mt-2" rows="9" readonly></textarea>
                    <button class="btn btn-secondary mt-2 copy-btn" data-target="publicKey-ED25519">Copy Public Key</button>
                </div>
            </div>
        </div>
    </div>

    <div class="card mt-4">
        <div class="card-header">
            <h3 class="card-title">Generating an RSA Public/Private keypair</h3>
        </div>
        <div class="card-body">
            <form id="keyForm">
                <center><button type="submit" class="btn btn-primary">Generate Keys</button></center>
            </form>
        </div>
        <div class="card-footer">
            <div class="row">
                <div class="col-sm-6">
                    <label for="privateKey"><b>Private Key:</b></label>
                    <textarea id="privateKey-RSA" class="form-control mt-2" rows="9" readonly></textarea>
                    <button class="btn btn-secondary mt-2 copy-btn" data-target="privateKey-RSA">Copy Private Key</button>
                </div>
                <div class="col-sm-6">
                    <label for="publicKey"><b>Public Key:</b></label>
                    <textarea id="publicKey-RSA" class="form-control mt-2" rows="9" readonly></textarea>
                    <button class="btn btn-secondary mt-2 copy-btn" data-target="publicKey-RSA">Copy Public Key</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        $(document).ready(function () {
            $('#keyFormED25519').submit(function (e) {
                e.preventDefault();
                $.post('', { action: 'generate_keys_ED25519' }, function (data) {
                    $('#privateKey-ED25519').val(data.private_key);
                    $('#publicKey-ED25519').val(data.public_key);
                }, 'json');
            });

            $('#keyForm').submit(function (e) {
                e.preventDefault();
                $.post('', { action: 'generate_keys' }, function (data) {
                    $('#privateKey-RSA').val(data.private_key);
                    $('#publicKey-RSA').val(data.public_key);
                }, 'json');
            });

            $('.copy-btn').click(function () {
                let targetId = $(this).data('target');
                let textArea = document.getElementById(targetId);
                textArea.select();
                document.execCommand('copy');
                $(this).text('Copied!').delay(1500).queue(function(next){
                    $(this).text('Copy ' + targetId.replace('Key', ' Key')).dequeue();
                });
            });
        });
    </script>
</body>
</html>
