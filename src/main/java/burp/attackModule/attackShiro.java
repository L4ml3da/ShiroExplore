package burp.attackModule;

import burp.scanner.Shiro550;
import burp.utils.ShiroExpCfg;
import burp.utils.ShiroLog;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

public abstract class attackShiro extends Shiro550 {

        public abstract void dnslogVerify() throws IOException;
        public abstract void commandExcute() throws IOException;
        public abstract void printConfig();
}