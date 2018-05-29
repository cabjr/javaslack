/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack.slack;

import com.github.seratch.jslack.Slack;
import com.github.seratch.jslack.api.methods.SlackApiException;
import com.github.seratch.jslack.api.methods.request.apps.permissions.AppsPermissionsInfoRequest;
import com.github.seratch.jslack.api.methods.request.apps.permissions.AppsPermissionsRequestRequest;
import com.github.seratch.jslack.api.methods.request.channels.ChannelsHistoryRequest;
import com.github.seratch.jslack.api.methods.request.channels.ChannelsListRequest;
import com.github.seratch.jslack.api.methods.request.chat.ChatPostMessageRequest;
import com.github.seratch.jslack.api.methods.request.files.FilesDeleteRequest;
import com.github.seratch.jslack.api.methods.request.files.FilesInfoRequest;
import com.github.seratch.jslack.api.methods.request.files.FilesRevokePublicURLRequest;
import com.github.seratch.jslack.api.methods.request.files.FilesSharedPublicURLRequest;
import com.github.seratch.jslack.api.methods.request.files.FilesUploadRequest;
import com.github.seratch.jslack.api.methods.request.im.ImHistoryRequest;
import com.github.seratch.jslack.api.methods.request.im.ImOpenRequest;
import com.github.seratch.jslack.api.methods.request.team.TeamInfoRequest;
import com.github.seratch.jslack.api.methods.request.users.UsersListRequest;
import com.github.seratch.jslack.api.methods.request.users.UsersSetPresenceRequest;
import com.github.seratch.jslack.api.methods.request.users.profile.UsersProfileGetRequest;
import com.github.seratch.jslack.api.methods.response.apps.permissions.AppsPermissionsInfoResponse;
import com.github.seratch.jslack.api.methods.response.channels.ChannelsHistoryResponse;
import com.github.seratch.jslack.api.methods.response.chat.ChatPostMessageResponse;
import com.github.seratch.jslack.api.methods.response.files.FilesDeleteResponse;
import com.github.seratch.jslack.api.methods.response.files.FilesInfoResponse;
import com.github.seratch.jslack.api.methods.response.files.FilesRevokePublicURLResponse;
import com.github.seratch.jslack.api.methods.response.files.FilesSharedPublicURLResponse;
import com.github.seratch.jslack.api.methods.response.files.FilesUploadResponse;
import com.github.seratch.jslack.api.methods.response.im.ImHistoryResponse;
import com.github.seratch.jslack.api.methods.response.im.ImOpenResponse;
import com.github.seratch.jslack.api.methods.response.team.TeamInfoResponse;
import com.github.seratch.jslack.api.methods.response.users.UsersSetPresenceResponse;
import com.github.seratch.jslack.api.methods.response.users.profile.UsersProfileGetResponse;
import com.github.seratch.jslack.api.model.Channel;
import com.github.seratch.jslack.api.model.User;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
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

    public void addScopeBot() {
        try {
            List<String> scopes = null;
            // https://api.slack.com/docs/oauth-scopes
            slack.methods().appsPermissionsRequest(AppsPermissionsRequestRequest.builder().token(token).scopes(scopes).build());
        } catch (IOException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public void listScopeInfo() {
        try {
            AppsPermissionsInfoResponse response = slack.methods().appsPermissionsInfo(AppsPermissionsInfoRequest.builder()
                    .token(token)
                    .build());
            System.out.println("response " + response);

        } catch (IOException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /*
    * presence: away ou auto
     */
    public boolean setUserPresence(String presence) {
        // Pode ser away ou auto
        try {
            //Manually sets user presence.
            UsersSetPresenceResponse response1 = slack.methods().usersSetPresence(
                    UsersSetPresenceRequest.builder().token(token).presence(presence).build());
            System.out.println("response1 " + response1);
            return true;
        } catch (IOException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public boolean getUserProfile() {
        // https://api.slack.com/methods/users.profile.get
        try {
            UsersProfileGetResponse response = slack.methods().usersProfileGet(UsersProfileGetRequest.builder().token(token).build());

            System.out.println("response1 " + response);
            return true;
        } catch (IOException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public void teamInfo() {
        try {
            TeamInfoResponse response = slack.methods().teamInfo(TeamInfoRequest.builder()
                    .token(token)
                    .build());
            System.out.println("Team " + response);
        } catch (IOException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public boolean deleteFile(String fileID) {
        try {
            FilesDeleteResponse response = slack.methods().filesDelete(FilesDeleteRequest.builder()
                    .token(token)
                    .file(fileID)
                    .build());
            System.out.println("fileDelete " + response);
            return response.isOk();
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public boolean infoFile(String fileID) {
        try {
            FilesInfoResponse response = slack.methods().filesInfo(FilesInfoRequest.builder()
                    .token(token)
                    .file(fileID)
                    .build());
            System.out.println("fileDelete " + response);
            return response.isOk();
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public boolean compartilharFile(String fileID) {
        try {

            FilesSharedPublicURLResponse response = slack.methods().filesSharedPublicURL(
                    FilesSharedPublicURLRequest.builder().token(token).file(fileID).build());
            System.out.println("fileDelete " + response);
            return response.isOk();
        } catch ( SlackApiException | IOException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public boolean revokePublicFile(String fileID) {
        try {

            FilesRevokePublicURLResponse response = slack.methods().filesRevokePublicURL(
                    FilesRevokePublicURLRequest.builder().token(token).file(fileID).build());
            System.out.println("revokePublicFile " + response);
            return response.isOk();
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    public boolean downloadFile(String fileID) {
        try {
            compartilharFile(fileID);
            FilesInfoResponse response = slack.methods().filesInfo(FilesInfoRequest.builder()
                    .token(token)
                    .file(fileID)
                    .build());
            System.out.println("response " + response);
            com.github.seratch.jslack.api.model.File f = response.getFile();
            String urlPublic = f.getPermalinkPublic();
            String[] separa = urlPublic.split("-");
            System.out.println("URL Code: " + separa[separa.length - 1]);
            String urlString = f.getUrlPrivate() + "?pub_secret=" + separa[separa.length - 1];
            System.out.println("URL Download" + urlString);
            URL url = new URL(urlString);
            String salve = "./" + f.getName();
            File file = new File(salve);
            FileUtils.copyURLToFile(url, file);
            revokePublicFile(fileID);
        } catch (MalformedURLException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(SlackImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return true;

    }

}
