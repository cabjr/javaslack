/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack;

import com.github.seratch.jslack.Slack;
import com.github.seratch.jslack.api.methods.SlackApiException;
import com.github.seratch.jslack.api.methods.request.channels.ChannelsListRequest;
import com.github.seratch.jslack.api.methods.response.channels.ChannelsListResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Douglas Folletto
 */
public class Teste {

    Slack slack = Slack.getInstance();
    String token = "xoxb-353804391270-364016632531-5FL3vzotYF1ste5VFi8G8fWf";
    ChannelsListResponse channelsResponse;

    public Teste() throws IOException, SlackApiException {
        this.channelsResponse = slack.methods().channelsList(ChannelsListRequest.builder().token(token).build());
        System.out.println("channelsResponse " + channelsResponse);
    }
    
    public static void main(String[] args) throws IOException {
        try {
            new Teste();
        } catch (SlackApiException ex) {
            Logger.getLogger(Teste.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
