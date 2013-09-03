/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.snow.maplesnowsniffer;

import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.Properties;

/**
 *
 * @author Administrator
 */
public class Lang {
    private static final Properties prop = new Properties();
    private static String lang_name = null;
    
    static {
        reloadValues();
    }
    
    public static void reloadValues() {
        load();//lang_name = MaplePcapture.getInstance().getSettings().getProperty("LANGUAGE");
        try {
            InputStreamReader is = new FileReader("languages/lng_"+ lang_name +".ini");
            prop.load(is);
            is.close();
        } catch (Exception e) {
            System.out.println("File not found: " + e);
        }
    }
    
    public static String get(String msgid) {
        return prop.getProperty(msgid);
    }
    
    public static boolean load() {
        Properties prop = new Properties();
        try {
            InputStreamReader is = new FileReader("settings.ini");
            prop.load(is);
            is.close();
        } catch (Exception e) {
            System.out.println(e);
        }
        lang_name = prop.getProperty("LANGUAGE");
    return true;
    }
}
