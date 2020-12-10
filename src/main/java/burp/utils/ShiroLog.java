package burp.utils;

import java.util.LinkedList;
import java.util.Queue;

public class ShiroLog {

    public Queue<String> Log = new LinkedList<String>();

    public enum LogType {
        FAILED,
        WARN,
        SUCCESS,
        INFO,
        CONFIG,
        DEBUG
    }

    public void LOG(LogType type, String logdetail){
        if(type == null || logdetail.length() == 0){
            return;
        }
        switch(type){
            case CONFIG:
                Log.offer("  [CONFIG]: " + logdetail + "\n");
                break;
            case FAILED:
                Log.offer("  [FAILED]: " + logdetail + "\n");
                break;
            case SUCCESS:
                Log.offer("  [SUCCESS]: " + logdetail + "\n");
                break;
            case WARN:
                Log.offer("  [WARN]:    " + logdetail + "\n");
                break;
            case INFO:
                Log.offer("  [INFO]:    " + logdetail + "\n");
                break;
            case DEBUG:
                Log.offer("  [DEBUG]:    " + logdetail + "\n");
                break;
        }
    }

    public String getLog(){
        StringBuilder tlog = new StringBuilder();
        while (!Log.isEmpty()){
            tlog.append(Log.poll());
        }
        return tlog.toString();
    }
}
