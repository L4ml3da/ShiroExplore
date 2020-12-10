package burp.utils;

import burp.scanner.Shiro550;
import com.unboundid.util.Base64;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.util.ByteSource;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEnDe
{
    public static String Encrypt(String payload, String key, ShiroExpCfg.ShiroCryptType ctype)
    {
        switch (ctype){
            case AES_CBC:
                try
                {
                    byte[] raw = Base64.decode(key);
                    byte[] ivs = Base64.decode("yHL9GLg7SDyGjnJrKKAprA==");
                    SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    IvParameterSpec iv = new IvParameterSpec(ivs);
                    cipher.init(1, skeySpec, iv);
                    byte[] encrypted = cipher.doFinal(pad(Base64.decode(payload)));
                    return Base64.encode(byteMerger(ivs, encrypted));
                }
                catch (Exception e) {}
                return "eHg=";
            case AES_GCM:
                try {
                    AesCipherService cipherService = new AesCipherService();
                    ByteSource byteSource = cipherService.encrypt(Base64.decode(payload), Base64.decode(key));
                    byte[] value = byteSource.getBytes();
                    return Base64.encode(value);
                }
                catch (Exception e) {}
        }
        return "";
    }

    public static byte[] pad(byte[] s)
    {
        s = byteMerger(s, charToByte((char)(16 - s.length % 16)));
        return s;
    }

    public static byte[] charToByte(char c)
    {
        byte[] b = new byte[2];
        b[0] = ((byte)((c & 0xFF00) >> '\b'));
        b[1] = ((byte)(c & 0xFF));
        return b;
    }

    public static byte[] byteMerger(byte[] bt1, byte[] bt2)
    {
        byte[] bt3 = new byte[bt1.length + bt2.length];
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);
        return bt3;
    }
}
