/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack.rtm;

import com.github.seratch.jslack.Slack;
import com.github.seratch.jslack.api.rtm.RTMClient;
import com.github.seratch.jslack.api.rtm.RTMMessageHandler;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Douglas Folletto
 */
public class RTMRunnable implements Runnable {

    // Não funcionou por causa de scope,
    // não encontrei a permissão necessaria
    
    private final Slack slack;
    private final String token;
    private static final int SLEEP_MILLIS = 100;

    public RTMRunnable(Slack slack, String token) {
        this.slack = slack;
        this.token = token;
    }

    @Override
    public void run() {

        try {
            JsonParser jsonParser = new JsonParser();
            RTMClient rtm = slack.rtmStart(token);

            RTMMessageHandler handler1 = (message) -> {
                JsonObject json = jsonParser.parse(message).getAsJsonObject();
                if (json.get("type") != null) {
                    System.out.println("Handled type: {}" + json.get("type").getAsString());
                }
            };
            RTMMessageHandler handler2 = (message) -> {
                System.out.println("Hello!");
            };
            rtm.addMessageHandler(handler1);
            rtm.addMessageHandler(handler1);
            rtm.addMessageHandler(handler2);
            rtm.connect();
            Thread.sleep(SLEEP_MILLIS);
            // Try anything on the channel...

            rtm.removeMessageHandler(handler2);

            Thread.sleep(SLEEP_MILLIS);
        } catch (IOException | InterruptedException ex) {
            Logger.getLogger(RTMRunnable.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
