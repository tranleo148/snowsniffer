package org.snow.maplesnowsniffer;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

/**
 *
 * @author anhtanh95
 */
public class GMSKeys {

    public static Map<Integer, byte[]> MapleStoryGlobalKeys = new HashMap<Integer, byte[]>();
    public static final String KeyURL = "http://direct.craftnet.nl/app_updates/get_keys.php";
    public static byte[] GetKeyForVersion(short mapleVer) {
        if (MapleStoryGlobalKeys.isEmpty()){
            Initialize();
        }
        if (MapleStoryGlobalKeys.containsKey((int) mapleVer)) {
            byte[] key = MapleStoryGlobalKeys.get((int) mapleVer);
            byte[] ret = new byte[32];
            for (int i = 0; i < 8; i++) {
                ret[i * 4] = key[i];
            }
            return ret;
        } else {
            return null;
        }
    }

    public static void Initialize() {
        File f = new File("noupdate.txt");// Trigger offline file loading
        if (!f.exists()) {
            try {
                //Load keys from url
                URL url = new URL(KeyURL);
                String str = "";
                Scanner sc = new Scanner(new InputStreamReader(url.openStream()));
                while (sc.hasNextLine()) {
                    str = str + sc.nextLine() + "\r\n";
                }
                InitByContents(str);
                sc.close();
                //Save keys to text file
                File file = new File("cached_keys.txt");
                if (!file.exists()) {
                    file.createNewFile();
                }
                FileWriter fw = new FileWriter(file.getAbsoluteFile());
                BufferedWriter bw = new BufferedWriter(fw);
                bw.write(str);
                bw.close();
            } catch (IOException ex) {
                System.out.println(ex);
            }
        } else {
            try {
                String text = "";
                Scanner input = new Scanner(f);
                while (input.hasNextLine()) {
                    text = text + input.nextLine() + "\r\n";
                }
                InitByContents(text);
                input.close();
            } catch (IOException ex) {
                System.out.println("Unable to load GMS Keys, because there were no cached keys stored and I failed retrieving them from the webserver! D:\r\nYou might want to check your internet connection and see if you can access http://direct.craftnet.nl/ directly.");
            }
        }
        // v118 Full key's lost
        MapleStoryGlobalKeys.put(118, new byte[]{
                    (byte) 0x5A, (byte) 0x22, (byte) 0xFB, (byte) 0xD1,
                    (byte) 0x8F, (byte) 0x93, (byte) 0xCD, (byte) 0xE6,});

    }

    private static void InitByContents(String str) {
        String[] lines = str.split("\r\n");
        for (int i = 0; i < lines.length; i += 2) {
            int version = Integer.parseInt(lines[i]);
            String tmpkey = lines[i + 1];
            String[] TMPkey = tmpkey.split("");
            byte[] realkey = new byte[8];
            int tmp = 0;
            for (int j = 1; j < 4 * 2 * 8; j += 4 * 2) // j = 1 because: if j = 0 => TMPkey[0] = ""
            {
                realkey[tmp++] = (byte) Integer.parseInt(TMPkey[j] + "" + TMPkey[j + 1], 16);
            }
            MapleStoryGlobalKeys.put(version, realkey);
        }
    }
}
