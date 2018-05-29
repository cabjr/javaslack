/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack.slack;

import com.github.seratch.jslack.Slack;
import com.github.seratch.jslack.api.methods.SlackApiException;
import com.github.seratch.jslack.api.methods.request.channels.ChannelsHistoryRequest;
import com.github.seratch.jslack.api.methods.request.channels.ChannelsListRequest;
import com.github.seratch.jslack.api.methods.request.chat.ChatPostMessageRequest;
import com.github.seratch.jslack.api.methods.request.files.FilesUploadRequest;
import com.github.seratch.jslack.api.methods.request.im.ImHistoryRequest;
import com.github.seratch.jslack.api.methods.request.im.ImOpenRequest;
import com.github.seratch.jslack.api.methods.request.users.UsersListRequest;
import com.github.seratch.jslack.api.methods.response.channels.ChannelsHistoryResponse;
import com.github.seratch.jslack.api.methods.response.chat.ChatPostMessageResponse;
import com.github.seratch.jslack.api.methods.response.files.FilesUploadResponse;
import com.github.seratch.jslack.api.methods.response.im.ImHistoryResponse;
import com.github.seratch.jslack.api.methods.response.im.ImOpenResponse;
import com.github.seratch.jslack.api.model.Channel;
import com.github.seratch.jslack.api.model.User;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import pt.ipb.ssi.chatslack.gui.Chat_2;

/**
 *
 * @author Douglas Folletto
 */
public class SlackImpl {

    String botUserToken, token;
    Slack slack;

    public SlackImpl(String botUserToken, String token) {
        this.botUserToken = botUserToken;
        this.token = token;
        this.slack = Slack.getInstance();
    }

    public List<Channel> getListChannels() {
        List<Channel> channels = null;
        try {
            channels = slack.methods().channelsList(ChannelsListRequest.builder().token(botUserToken).build())
                    .getChannels();
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return channels;
    }

    public List<User> getListUsers() {
        List<User> users = null;
        try {
            users = slack.methods().usersList(UsersListRequest.builder().token(botUserToken).build())
                    .getMembers();
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return users;
    }

    public boolean sendMessage(String channel, String msg_encrypt) {
        ChatPostMessageResponse resp = new ChatPostMessageResponse();
        resp.setOk(false);
        try {
            resp = slack.methods().chatPostMessage(
                    ChatPostMessageRequest.builder()
                            .asUser(false)
                            .text(msg_encrypt)
                            //.username("BotRandom")
                            .token(token).channel(channel).build());
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return resp.isOk();
    }

    public String getChannelByUser(String userID) {
        try {
            ImOpenResponse canal = slack.methods().imOpen(ImOpenRequest.builder().user(userID).token(token).build());
            return canal.getChannel().getId();
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(Chat_2.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }

    public ChannelsHistoryResponse getChannelHistory(String channelID) {
        try {
            ChannelsHistoryResponse history = slack.methods()
                    .channelsHistory(ChannelsHistoryRequest.builder()
                            .token(token)
                            .channel(channelID)
                            .count(5)
                            .build());
            return history;
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(Chat_2.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public ImHistoryResponse getChannelDM(String userID) {
        try {
            ImOpenResponse canal = slack.methods().imOpen(ImOpenRequest.builder().user(userID).token(token).build());
            if (canal.getChannel().getId() != null) {
                ImHistoryResponse history = slack.methods().imHistory(
                        ImHistoryRequest.builder()
                                .channel(canal.getChannel().getId())
                                .token(token)
                                .count(1000)
                                .build());
                return history;
            }

        } catch (IOException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public boolean sendFile(File file, List<String> channel, String title) {
        FilesUploadResponse resp = new FilesUploadResponse();
        resp.setOk(false);
        try {
            resp = slack.methods().filesUpload(FilesUploadRequest.builder()
                    .token(token)
                    .channels(channel)
                    .file(file)
                    .filename(file.getName())
                    .title(title)
                    .build());
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return resp.isOk();
    }

}
