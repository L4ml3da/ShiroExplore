package burp;


import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import burp.scanner.Shiro550;
import burp.scanner.Shiro721;
import burp.utils.ShiroExpCfg;
import burp.utils.ShiroExpCfg.ScanType;


public class BurpExtender implements IBurpExtender, IScannerCheck, ITab{

    private ShiroExpGUI shiroExpGUI;
    private IBurpExtenderCallbacks callbacks;

    public HashMap<String, HashMap<ShiroExpCfg.ScanType, ScanState>> scan_record = new HashMap<>();

    private enum ScanState{
        Pending,
        VULNERABLE,
        SAFE
    }



    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Shiro Explore");
        shiroExpGUI = new ShiroExpGUI(callbacks);
        this.callbacks = callbacks;
        callbacks.addSuiteTab(this);
        callbacks.registerScannerCheck(this);
        callbacks.printOutput(
                "[+] Shiro Explore load success\n" +
                "[+] Good Luck ^_^\n" +
                "[+]\n" +
                "[+] #####################################\n" +
                "[+]    Shiro Explore v1.0\n" +
                "[+]    author: Lambda\n" +
                "[+] ####################################\n");
    }

    @Override
    public String getTabCaption() {
        return "Shiro Explore";
    }

    @Override
    public Component getUiComponent() {
        return shiroExpGUI.$$$getRootComponent$$$();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        HashMap<ScanType, ScanState> vuln_record = new HashMap<ScanType, ScanState>();
        List<IScanIssue> issues = new ArrayList<>(2);
        IHttpService http_service = baseRequestResponse.getHttpService();;
        String target_host = http_service.getHost() + ":" + http_service.getPort();

        callbacks.printOutput("in host: " + target_host);

        if(scan_record.containsKey(target_host)){
            HashMap<ScanType, ScanState> tmp_vuln_record = scan_record.get(target_host);
            if(tmp_vuln_record.containsKey(ScanType.SHIRO_550_V1)) {
                if(tmp_vuln_record.get(ScanType.SHIRO_550_V1) == ScanState.Pending ||
                        tmp_vuln_record.get(ScanType.SHIRO_550_V1) == ScanState.SAFE){
                    return null;
                }
            }
            if(tmp_vuln_record.containsKey(ScanType.SHIRO_550_V2)) {
                if(tmp_vuln_record.get(ScanType.SHIRO_550_V2) == ScanState.Pending ||
                        tmp_vuln_record.get(ScanType.SHIRO_550_V2) == ScanState.SAFE){
                    return null;
                }
            }
        } else {
            vuln_record.put(ScanType.SHIRO_550_V1, ScanState.Pending);
            vuln_record.put(ScanType.SHIRO_550_V2, ScanState.Pending);
            scan_record.put(target_host, vuln_record);
        }

        Shiro550 shiro550V1_scanner = new Shiro550(callbacks, baseRequestResponse, ScanType.SHIRO_550_V1);
        Shiro550 shiro550V2_scanner = new Shiro550(callbacks, baseRequestResponse, ScanType.SHIRO_550_V2);

        Shiro721 shiro721_scanner = new Shiro721(callbacks, baseRequestResponse);

        if(shiro550V1_scanner.shiro_frame_confirm() ||shiro550V2_scanner.shiro_frame_confirm()) {
            callbacks.printOutput("v1 start scan");
            shiro550V1_scanner.start_scan();
            if (shiro550V1_scanner.isShiroVulnDetected()) {
                callbacks.printOutput("v1 verify");
                vuln_record.put(ScanType.SHIRO_550_V1, ScanState.VULNERABLE);
                scan_record.put(target_host, vuln_record);
                issues.add(shiro550V1_scanner.get_issue());
            } else {
                callbacks.printOutput("v2 start scan");
                shiro550V2_scanner.setShiroFrameDetected(true);
                shiro550V2_scanner.start_scan();
                if (shiro550V2_scanner.isShiroVulnDetected()) {
                    callbacks.printOutput("v2 verify");
                    vuln_record.put(ScanType.SHIRO_550_V2, ScanState.VULNERABLE);
                    scan_record.put(target_host, vuln_record);
                    issues.add(shiro550V2_scanner.get_issue());
                } else {
                    vuln_record.put(ScanType.SHIRO_550_V1, ScanState.SAFE);
                    vuln_record.put(ScanType.SHIRO_550_V2, ScanState.SAFE);
                    scan_record.put(target_host, vuln_record);
                }
            }
        }
            /*
        if(scan_record.containsKey(target_host)) {
            HashMap<ScanType, ScanState> vuln_record = scan_record.get(target_host);
            if (vuln_record.containsKey(ScanType.IGNORE) ||
                    (vuln_record.get(ScanType.SHIRO_550_V1) == ScanState.SAFE &&
                            vuln_record.get(ScanType.SHIRO_721) == ScanState.SAFE)) {
                return null;
            }

            if(vuln_record.get(ScanType.SHIRO_721) == ScanState.Pending && shiro721_scanner.shiro_cookie_valid()){
                    shiro721_scanner.start_scan();
                    if(shiro721_scanner.isShiroVulnDetected()){
                        vuln_record.put(ScanType.SHIRO_721, ScanState.VULNERABLE);
                        scan_record.put(target_host, vuln_record);
                        issues.add(shiro721_scanner.get_issue());
                    }else {
                        vuln_record.put(ScanType.SHIRO_721, ScanState.SAFE);
                        scan_record.put(target_host, vuln_record);
                    }
            }
        }else{
            HashMap<ScanType, ScanState> vuln_record = new HashMap<ScanType, ScanState>();
            if(shiro550V1_scanner.shiro_frame_confirm()){
                callbacks.printOutput("v1 start scan");
                shiro550V1_scanner.start_scan();
                if (shiro550V1_scanner.isShiroVulnDetected()) {
                    callbacks.printOutput("v1 verify");
                    vuln_record.put(ScanType.SHIRO_550_V1, ScanState.VULNERABLE);
                    scan_record.put(target_host, vuln_record);
                    issues.add(shiro550V1_scanner.get_issue());
                } else {
                    callbacks.printOutput("v2 start scan");
                    shiro550V2_scanner.start_scan();
                    if (shiro550V2_scanner.isShiroVulnDetected()) {
                        callbacks.printOutput("v2 verify");
                        vuln_record.put(ScanType.SHIRO_550_V2, ScanState.VULNERABLE);
                        scan_record.put(target_host, vuln_record);
                        issues.add(shiro550V2_scanner.get_issue());
                    } else {
                        vuln_record.put(ScanType.SHIRO_550_V1, ScanState.SAFE);
                        vuln_record.put(ScanType.SHIRO_550_V2, ScanState.SAFE);
                        scan_record.put(target_host, vuln_record);
                    }
                }
                if(shiro721_scanner.shiro_cookie_valid()){
                    shiro721_scanner.start_scan();
                    if(shiro721_scanner.isShiroVulnDetected()){
                        vuln_record.put(ScanType.SHIRO_721, ScanState.VULNERABLE);
                        scan_record.put(target_host, vuln_record);
                        issues.add(shiro721_scanner.get_issue());
                    }else {
                        vuln_record.put(ScanType.SHIRO_721, ScanState.SAFE);
                        scan_record.put(target_host, vuln_record);
                    }
                } else{
                    vuln_record.put(ScanType.SHIRO_721, ScanState.Pending);
                    scan_record.put(target_host, vuln_record);
                }
            }else{
                vuln_record.put(ScanType.IGNORE, ScanState.SAFE);
                scan_record.put(target_host, vuln_record);
                return null;
            }
        }

             */

        callbacks.printOutput("scan target host : " + shiro550V1_scanner.target_host);
        if(issues.isEmpty()) return null;
        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
}
