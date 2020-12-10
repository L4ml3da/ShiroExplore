package burp.scanner;

import burp.*;
import burp.utils.ShiroExpCfg;
import burp.utils.ShiroLog;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.net.HttpCookie;
import java.util.*;

public class ShiroScan extends ShiroLog {
    public IExtensionHelpers helpers;
    public IHttpService http_service;
    public IBurpExtenderCallbacks callbacks;
    public IHttpRequestResponse baseReqResp;

    public String target_host = "";
    public String target_url = "";
    public String rememberMeCookie = "";
    public String gadgetType = "";
    public String command = "";
    public String validKey = "";

    private boolean ShiroVulnDetected = false;
    private boolean ShiroFrameDetected = false;
    public List<String> shiroHeader = new ArrayList<String>();;

    public String vuln_name = "";
    public String serverity = "";
    public String confidence = "";
    public String issueDetail = "";
    public String remediationDetail = "";


    public boolean isShiroFrameDetected() {
        return ShiroFrameDetected;
    }

    public void setShiroFrameDetected(boolean shiroFrameDetected) {
        ShiroFrameDetected = shiroFrameDetected;
    }


    public boolean isShiroVulnDetected() {
        return ShiroVulnDetected;
    }

    public void setShiroVulnDetected(boolean shiroVulnDetected) {
        ShiroVulnDetected = shiroVulnDetected;
    }

    public ShiroScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseReqResp) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.baseReqResp = baseReqResp;
        this.http_service = baseReqResp.getHttpService();;
        this.target_host = http_service.getHost() + ":" + http_service.getPort();
        this.target_url = http_service.getProtocol() + "://" + http_service.getHost() + ":" + http_service.getPort();
        this.baseInfoParser();
    }
    public ShiroScan(){
    }

    public String payloadSend(String url, String cookieValue){
        int retry = 3;
        OkHttpClient httpClient = new OkHttpClient();
        Response response = null;
        Request request = new Request.Builder().url(url).
                header("Cookie", "rememberMe=" + cookieValue)
                .build();
        while(retry-- != 0){
            try {
                response = httpClient.newCall(request).execute();
            }catch (Exception e) {
                e.printStackTrace();
            }
            if(response != null) {
                String head =  response.headers().toString();
                response.close();
                return head;
            }
        }
        return null;
    }

    public IResponseInfo shiroSendRequest(List<String> attackHeaders, byte[] data){
        byte[] httpMessage = helpers.buildHttpMessage(attackHeaders, data);
        IHttpRequestResponse resp = callbacks.makeHttpRequest(http_service, httpMessage);
        byte[] httpResponse = resp.getResponse();

        return helpers.analyzeResponse(httpResponse);
    }

    public boolean shiro_frame_confirm() {

        List<String> testHeader = CustomShiroCookieHeader("test");

        byte[] httpMessage = helpers.buildHttpMessage(testHeader, null);

        IHttpRequestResponse resp = callbacks.makeHttpRequest(http_service, httpMessage);

        byte[] httpResponse = resp.getResponse();

        IResponseInfo shiroInfo = helpers.analyzeResponse(httpResponse);
        List<ICookie> cookies = shiroInfo.getCookies();
        for(ICookie cookie : cookies){
            callbacks.printOutput(cookie.getName());
            callbacks.printOutput(cookie.getValue());
            if(cookie.getName().contains("rememberMe")){
                setShiroFrameDetected(true);
                callbacks.printOutput("contains");
                return true;
            }
            else{
                callbacks.printOutput("not contains");
                return false;
            }
        }
        return false;
    }

    public List<String> CustomShiroCookieHeader(String cookieValue){
        List<String> CustomHeader = new ArrayList<String>(shiroHeader);
        CustomHeader.removeIf(tmpHeader -> tmpHeader.toUpperCase().contains("COOKIE"));
        CustomHeader.add("Cookie: rememberMe=" + cookieValue);
        return CustomHeader;
    }

    public void baseInfoParser(){
        IRequestInfo requestInfo = helpers.analyzeRequest(baseReqResp.getRequest());
        List<String> reqHeaders = requestInfo.getHeaders();


        shiroHeader.addAll(reqHeaders);

        for(String header: reqHeaders){
            if(header.toUpperCase().contains("COOKIE") &&
                header.contains("rememberMe=")){
                    try {
                        String[] cstring = header.split("rememberMe=");
                        if(cstring[1].contains(";")){
                            rememberMeCookie = cstring[1].split(";")[0];
                        }else{
                            rememberMeCookie = cstring[1];
                        }
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
        }


    public String vuln_verify(ShiroExpCfg.EngineModel model){
        return "";
    }

    public void start_scan(){
    }

    public IScanIssue get_issue(){
        return null;
    }
}
