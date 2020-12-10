package burp.scanner;

import burp.*;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;

public class Shiro721 extends ShiroScan{

    private IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
    private String ValidHexRememberMeCookie = "";
    private String verifyPayload = "";

    public Shiro721(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseReqResp) {
        super(callbacks, baseReqResp);
        vuln_name = "Shiro 721 RCE";
        serverity = "Low";
        confidence = "Certain";
        issueDetail = "Target host is vulnerable by Apache shiro version \n" +
                "1.2.5, 1.2.6, 1.3.0, 1.3.1, 1.3.2, 1.4.0-RC2, 1.4.0, 1.4.1 ";
    }

    public boolean shiro_cookie_valid(){

        callbacks.printOutput("verify cookie valid!!");

        if(rememberMeCookie.length() == 0){
            return false;
        }else{
            List<String> testHeader = CustomShiroCookieHeader(rememberMeCookie);
            shiroSendRequest(testHeader, null);

            IResponseInfo shiroResp = shiroSendRequest(testHeader, null);;
            List<String> respHeader = shiroResp.getHeaders();
            for(String tmpLine:respHeader){
                if(tmpLine.contains("rememberMe=deleteMe")){
                    callbacks.printOutput("rememberMe cookie invalid");
                    return false;
                }
            }
            callbacks.printOutput("rememberMe cookie valid");

            ValidHexRememberMeCookie = Hex.encodeHexString(Base64.decodeBase64(rememberMeCookie));

            return true;
        }
    }

    public void vuln_detect() {

        if(ValidHexRememberMeCookie.length() == 0) return;

        AtomicReference<String> iv_word = new AtomicReference<>("");
        AtomicBoolean validIV = new AtomicBoolean(true);
        callbacks.printOutput("shiro721 detect start");
        IntStream.range(0, 256).forEach(n -> {
            validIV.set(true);
            iv_word.set(String.format("%02X", (0xFF & n)));
            String tmp_cookie = ValidHexRememberMeCookie + StringUtils.repeat("0", 30) + iv_word + StringUtils.repeat("0", 32);

            byte[] bytes = null;
            try {
                bytes = Hex.decodeHex(tmp_cookie.toCharArray());
            } catch (DecoderException e) {
                e.printStackTrace();
            }
            String payload = Base64.encodeBase64String(bytes);;
            List<String> attackHeader = CustomShiroCookieHeader(payload);
            IResponseInfo shiroResp = shiroSendRequest(attackHeader, null);
            List<String> respHeader = shiroResp.getHeaders();
            for(String tmpLine:respHeader){
                if(tmpLine.contains("rememberMe=deleteMe")){
                    callbacks.printOutput("wrong iv word " + iv_word);
                    validIV.set(false);
                    break;
                }
            }
            if(validIV.get()){
                verifyPayload = payload;
                setShiroVulnDetected(true);
                callbacks.printOutput("right iv word" + iv_word + " found and it's vulnerable!" );
                return;
            }
        }
        );
    }

    @Override
    public void start_scan() {
        vuln_detect();
        if(isShiroVulnDetected()) {
            serverity = "High";
            remediationDetail = "Test the one valid Oracle Padding String by payload: " + verifyPayload;
        }
    }

    @Override
    public IScanIssue get_issue() {
        return new ShiroScanIssue(
                http_service,
                helpers.analyzeRequest(baseReqResp).getUrl(),
                new IHttpRequestResponse[] { callbacks.applyMarkers(baseReqResp, null, null) },
                vuln_name,
                serverity,
                confidence,
                issueDetail ,
                remediationDetail);
    }

}
