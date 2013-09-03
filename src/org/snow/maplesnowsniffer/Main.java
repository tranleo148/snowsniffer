/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package org.snow.maplesnowsniffer;

import org.snow.odinms.ListDevices;
import org.snow.odinms.MapleOpcodeView;
import org.snow.odinms.MaplePcapture;

/**
 *
 * @author Raz
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try {
            if (args.length > 0) {
                String program = args[0];
                String[] argsNew = new String[args.length - 1];
                for(int i = 1; i < args.length; i++) {
                    argsNew[i - 1] = args[i];
                }

                if (program.equals("sniffer")) {
                 MaplePcapture.main(argsNew);
                } else if (program.equals("listdevices")) {
                    ListDevices.main(argsNew);
                } else if (program.equals("opcodeview")) {
                    MapleOpcodeView.main(argsNew);
                } else {
                    System.out.println("Unknown starting argument");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
