<?php

require 'vendor/autoload.php';

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;

// Generate a unique file name for the key pair
$uniqueId = uniqid();
$privateKeyFile = __DIR__ . "/private_{$uniqueId}.pem";
$publicKeyFile = __DIR__ . "/public_{$uniqueId}.pem";
$signatureFile = __DIR__ . "/signature_{$uniqueId}.txt";

// Generate RSA key pair
function generateKeyPair($privateKeyFile, $publicKeyFile) {
    
    // Generate a new RSA private key (4096 bits)
    $privateKey = RSA::createKey(4096);
    $privateKey = $privateKey->withHash('sha256')->withPadding(RSA::SIGNATURE_PKCS1);
    file_put_contents($privateKeyFile, $privateKey);

    // Extract the private and public keys
    $publicKey = $privateKey->getPublicKey();
    $publicKey = $publicKey->withHash('sha256')->withPadding(RSA::SIGNATURE_PKCS1);
    file_put_contents($publicKeyFile, $publicKey);

    return array('privateKey' => $privateKey, 'publicKey' => $publicKey);
}

function generateSignature($nonce, $privateKey) {

    $privateKey = PublicKeyLoader::loadPrivateKey($privateKey)->withHash('sha256')->withPadding(RSA::SIGNATURE_PKCS1);
    $encryptedNonce = $privateKey->sign($nonce);
    return $encryptedNonce;
}

function verifySignature($nonce, $signature, $publicKey) {

    $publicKey = PublicKeyLoader::loadPublicKey($publicKey)->withHash('sha256')->withPadding(RSA::SIGNATURE_PKCS1);
    $verified = $publicKey->verify($nonce, $signature);
    return $verified;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    if ($_POST['action'] === 'generate_keys') {
        $keyPair = generateKeyPair($privateKeyFile, $publicKeyFile);
        echo json_encode(['private_key' => file_get_contents($privateKeyFile), 'public_key' => file_get_contents($publicKeyFile)]);
        unlink($privateKeyFile);
        unlink($publicKeyFile);
        exit;
    }
    
    if ($_POST['action'] === 'encrypt_nonce') {
        $nonce = $_POST['nonce'];
        $privateKey = $_POST['private_key'];
        $signature = generateSignature($nonce, $privateKey);
        echo json_encode(['signature' => base64_encode($signature)]);
        exit;
    }

    if ($_POST['action'] === 'verify_nonce') {
        $nonce = $_POST['nonce'];
        $signature = $_POST['signature'];
        $publicKey = $_POST['public_key'];
        $verification = verifySignature($nonce, base64_decode($signature), $publicKey);
        echo json_encode(['verified' => $verification]);
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
            <h3 class="card-title">Generate Public/Private keypair</h3>
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
                    <textarea id="privateKey" class="form-control mt-2" rows="10" readonly></textarea>
                    <button class="btn btn-secondary mt-2 copy-btn" data-target="privateKey">Copy Private Key</button>
                </div>
                <div class="col-sm-6">
                    <label for="publicKey"><b>Public Key:</b></label>
                    <textarea id="publicKey" class="form-control mt-2" rows="10" readonly></textarea>
                    <button class="btn btn-secondary mt-2 copy-btn" data-target="publicKey">Copy Public Key</button>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-sm-6">
            <div class="card mt-3">
                <div class="card-header">
                    <h3 class="card-title">Generate Nonce Signature</h3>
                </div>
                <div class="card-body">
                    <form id="encryptForm">
                        <input type="text" name="nonce" id="nonce" class="form-control" placeholder="Enter Nonce" required>
                        <button type="submit" class="btn btn-success mt-2">Encrypt</button>
                    </form>
                </div>
                <div class="card-footer">
                    <label for="signature"><b>Signature:</b></label>
                    <textarea id="signature" class="form-control mt-2" rows="7" readonly></textarea>
                    <button class="btn btn-secondary mt-2 copy-btn" data-target="signature">Copy Signature</button>
                </div>
            </div>
        </div>
        <div class="col-sm-6">
            <div class="card mt-3">
                <div class="card-header">
                    <h3 class="card-title">Verify Signature</h3>
                </div>
                <div class="card-body">
                    <form id="verifiedForm">
                        <button type="submit" class="btn btn-success mt-2">Verify</button>
                    </form>
                </div>
                <div class="card-footer">
                    <label for="verified"><b>Verified:</b></label>
                    <textarea id="verified" class="form-control mt-2" rows="1" readonly></textarea>
                    <p class="text-muted mt-3"><b>Note: </b>This section is for testing purposes only. It is intended to check whether the functionality is working or not. If it does not work here, it will not work on the Hub server either.</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        $(document).ready(function () {
            $('#keyForm').submit(function (e) {
                e.preventDefault();
                $.post('', { action: 'generate_keys' }, function (data) {
                    $('#privateKey').val(data.private_key);
                    $('#publicKey').val(data.public_key);
                }, 'json');
            });

            $('#encryptForm').submit(function (e) {
                e.preventDefault();
                $.post('', {
                    action: 'encrypt_nonce',
                    nonce: $('#nonce').val(),
                    private_key: $('#privateKey').val()
                }, function (data) {
                    $('#signature').val(data.signature);
                }, 'json');
            });

            $('#verifiedForm').submit(function (e) {
                e.preventDefault();
                $.post('', {
                    action: 'verify_nonce',
                    nonce: $('#nonce').val(),
                    signature: $('#signature').val(),
                    public_key: $('#publicKey').val()
                }, function (data) {
                    $('#verified').val(data.verified);
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
