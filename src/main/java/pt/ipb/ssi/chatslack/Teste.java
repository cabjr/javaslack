/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ipb.ssi.chatslack.gnupg.Openpgp;
import pt.ipb.ssi.chatslack.gui.Login;

/**
 *
 * @author Douglas Folletto
 */
public class Teste {

    public static void main(String[] args) {
        //BC is the ID for the Bouncy Castle provider;
        Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BC") == null) {
            System.out.println("Bouncy Castle provider is NOT available");
        } else {
            System.out.println("Bouncy Castle provider is available");
        }
        new Login().setVisible(true);
    }
}
