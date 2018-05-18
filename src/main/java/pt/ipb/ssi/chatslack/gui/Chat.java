/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack.gui;

import com.github.seratch.jslack.Slack;
import com.github.seratch.jslack.api.methods.SlackApiException;
import com.github.seratch.jslack.api.methods.request.channels.ChannelsHistoryRequest;
import com.github.seratch.jslack.api.methods.request.channels.ChannelsListRequest;
import com.github.seratch.jslack.api.methods.request.chat.ChatPostMessageRequest;
import com.github.seratch.jslack.api.methods.request.conversations.ConversationsHistoryRequest;
import com.github.seratch.jslack.api.methods.request.im.ImHistoryRequest;
import com.github.seratch.jslack.api.methods.request.im.ImListRequest;
import com.github.seratch.jslack.api.methods.request.im.ImOpenRequest;
import com.github.seratch.jslack.api.methods.request.users.UsersListRequest;
import com.github.seratch.jslack.api.methods.response.channels.ChannelsHistoryResponse;
import com.github.seratch.jslack.api.methods.response.chat.ChatPostMessageResponse;
import com.github.seratch.jslack.api.methods.response.conversations.ConversationsHistoryResponse;
import com.github.seratch.jslack.api.methods.response.im.ImHistoryResponse;
import com.github.seratch.jslack.api.methods.response.im.ImListResponse;
import com.github.seratch.jslack.api.methods.response.im.ImOpenResponse;
import com.github.seratch.jslack.api.model.Channel;
import com.github.seratch.jslack.api.model.User;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import pt.ipb.ssi.chatslack.rtm.RTMRunnable;

/**
 *
 * @author Douglas Folletto
 */
public class Chat extends javax.swing.JFrame {

    String botUserToken, token;
    Slack slack;
    int CanalAtual = 0;
    int usuarioAtual = 0;
    Map<String, String> usuarioMap = new HashMap<>();

    DefaultListModel listModelCanais = new DefaultListModel();
    DefaultListModel listModelUsuarios = new DefaultListModel();
    ArrayList<Channel> canais = new ArrayList<Channel>();

    /**
     * Creates new form Chat
     *
     * @param botUserToken
     * @param token
     */
    public Chat(String botUserToken, String token) {
        initComponents();
        this.slack = Slack.getInstance();
        this.botUserToken = botUserToken;
        this.token = token;
        listCanais.setModel(listModelCanais);
        listDM.setModel(listModelUsuarios);

        setListChannel();
        setListUsers();
        setChatHistory();
        //setRTM();

        listCanais.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent arg0) {
                listDM.clearSelection();
                CanalAtual = listCanais.getSelectedIndex();
                setChatHistory();
            }
        });

        listDM.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                listCanais.clearSelection();
                usuarioAtual = listDM.getSelectedIndex();
                String userName = listDM.getSelectedValue();
                System.out.println("userName " + userName + " ID " + usuarioMap.get(userName));
                setDMChatHistory(usuarioMap.get(userName));
            }

        });

    }

    private void setDMChatHistory(String userID) {
        try {
            txtMsgRecebida.setText("");
            //Abre um canal para aquele usuario
            // Scope: 	bot, user: im:write post
            //
            ImHistoryResponse history;
            ImListResponse list = slack.methods().imList(ImListRequest.builder().token(token).build());
            if (list.getIms().size() > 0) {

                history = slack.methods().imHistory(ImHistoryRequest.builder().token(token).channel(list.getIms().get(0).getId()).build());
            } else {
                ImOpenResponse channelID = slack.methods().imOpen(ImOpenRequest.builder().token(token).user(userID).build());
                System.out.println(channelID);
                System.out.println(channelID.getChannel().getId());
                history = slack.methods().imHistory(ImHistoryRequest.builder().token(token).channel(channelID.getChannel().getId()).build());
            }

            System.out.println("history " + history);
            if (history.getMessages() != null) {
                for (int i = history.getMessages().size() - 1; i >= 0; i--) {
                    if (history.getMessages().get(i).getUsername() != null) {
                        txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": " + history.getMessages().get(i).getText() + "\n");
                    } else if (history.getMessages().get(i).getText().contains("<@")) {
                        txtMsgRecebida.append(/*name */" " + history.getMessages().get(i).getText() + "\n");

                    } else {
                        txtMsgRecebida.append(history.getMessages().get(i).getText() + "\n");
                    }
                }
                // }
            }
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    private void setListChannel() {
        try {
            listModelCanais.removeAllElements();
            canais.removeAll(canais);
            ListIterator<Channel> channels = (ListIterator<Channel>) slack.methods().channelsList(ChannelsListRequest.builder().token(botUserToken).build())
                    .getChannels().listIterator();
            while (channels.hasNext()) {
                Channel canal = channels.next();
                System.out.println(canal);
                if (canal != null) {
                    canais.add(canal);
                }
                listModelCanais.addElement(canal.getName());
            }
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void setListUsers() {
        try {
            List<User> users = slack.methods().usersList(UsersListRequest.builder().token(botUserToken).build())
                    .getMembers();
            System.out.println(slack.methods().usersList(UsersListRequest.builder().token(botUserToken).build()));
            for (User user : users) {
                if (!user.isBot()) {
                    listModelUsuarios.addElement(user.getName());
                    usuarioMap.put(user.getName(), user.getId());
                }
            }
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        txtMsgRecebida = new javax.swing.JTextArea();
        txtMsgEnviar = new javax.swing.JTextField();
        btnEnviar = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        listCanais = new javax.swing.JList<>();
        jScrollPane3 = new javax.swing.JScrollPane();
        listDM = new javax.swing.JList<>();
        jScrollPane4 = new javax.swing.JScrollPane();
        listApps = new javax.swing.JList<>();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Chat");

        txtMsgRecebida.setEditable(false);
        txtMsgRecebida.setColumns(20);
        txtMsgRecebida.setRows(5);
        jScrollPane1.setViewportView(txtMsgRecebida);

        btnEnviar.setText("Enviar");
        btnEnviar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEnviarActionPerformed(evt);
            }
        });

        jLabel1.setText("Canais");

        jLabel2.setText("DM");

        jLabel3.setText("Apps");

        listCanais.addPropertyChangeListener(new java.beans.PropertyChangeListener() {
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                listCanaisPropertyChange(evt);
            }
        });
        jScrollPane2.setViewportView(listCanais);

        jScrollPane3.setViewportView(listDM);

        jScrollPane4.setViewportView(listApps);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 142, Short.MAX_VALUE)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                    .addComponent(jLabel3))
                .addGap(46, 46, 46)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(txtMsgEnviar, javax.swing.GroupLayout.PREFERRED_SIZE, 383, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnEnviar))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 449, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(31, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 343, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtMsgEnviar, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnEnviar, javax.swing.GroupLayout.Alignment.TRAILING)))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 75, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 107, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(33, Short.MAX_VALUE))
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void btnEnviarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEnviarActionPerformed
        // Clique no botão de enviar
        if (!listCanais.isSelectionEmpty()) {

            String channelID = canais.get(CanalAtual).getId();
            if (!txtMsgEnviar.getText().isEmpty()) {
                String mensagem = txtMsgEnviar.getText();
                try {
                    slack.methods().chatPostMessage(ChatPostMessageRequest.builder().asUser(false).text(mensagem).username("TesteBotSDASDDAS").iconEmoji(":chart_with_upwards_trend:").asUser(true).token(botUserToken).channel(channelID).build());
                    setChatHistory();
                    txtMsgEnviar.setText("");
                } catch (IOException ex) {
                    Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SlackApiException ex) {
                    Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        } else {
            if (!txtMsgEnviar.getText().isEmpty()) {
                String channel = "";
                String userName = listDM.getSelectedValue();
                System.out.println("userName " + userName + " ID " + usuarioMap.get(userName));
                channel = usuarioMap.get(userName);
                String mensagem = txtMsgEnviar.getText();

                try {
                    slack.methods().chatPostMessage(ChatPostMessageRequest.builder().asUser(false).text(mensagem).username("TesteBotSDASDDAS").iconEmoji(":chart_with_upwards_trend:").asUser(true).token(botUserToken).channel(channel).build());
                } catch (IOException ex) {
                    Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SlackApiException ex) {
                    Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
                }
                setDMChatHistory(usuarioMap.get(userName).toString());
                txtMsgEnviar.setText("");
            }
        }
    }//GEN-LAST:event_btnEnviarActionPerformed

    private void listCanaisPropertyChange(java.beans.PropertyChangeEvent evt) {//GEN-FIRST:event_listCanaisPropertyChange

    }//GEN-LAST:event_listCanaisPropertyChange


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnEnviar;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JList<String> listApps;
    private javax.swing.JList<String> listCanais;
    private javax.swing.JList<String> listDM;
    private javax.swing.JTextField txtMsgEnviar;
    private javax.swing.JTextArea txtMsgRecebida;
    // End of variables declaration//GEN-END:variables

    private void setChatHistory() {
        if (listCanais.getSelectedIndex() != -1) {
            try {
                txtMsgRecebida.setText("");
                String channelID = canais.get(CanalAtual).getId();
                System.out.println(slack.methods().channelsHistory(ChannelsHistoryRequest.builder().token(botUserToken).build()).getMessages());
                ChannelsHistoryResponse history = slack.methods().channelsHistory(ChannelsHistoryRequest.builder()
                        .token(token)
                        .channel(channelID)
                        .count(1000)
                        .build());
                System.out.println(channelID);
                System.out.println(history);
                if (history.getMessages() != null) {
                    for (int i = history.getMessages().size() - 1; i >= 0; i--) {
                        if (history.getMessages().get(i).getUsername() != null) {
                            txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": " + history.getMessages().get(i).getText() + "\n");
                        } else if (history.getMessages().get(i).getText().contains("<@")) {

                            /*String pieces[] = history.getMessages().get(i).getText().split(">");
                        String name = slack.methods().usersProfileGet(UsersProfileGetRequest.builder().token(token).user(pieces[0].substring(2)).build()).getProfile().getDisplayName();
                        System.out.println(name);*/
                            txtMsgRecebida.append(/*name */" " + history.getMessages().get(i).getText() + "\n");

                        } else {
                            txtMsgRecebida.append(history.getMessages().get(i).getText() + "\n");
                        }
                    }
                }
            } catch (IOException | SlackApiException ex) {
                Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private void setRTM() {
        Thread thread = new Thread(new RTMRunnable(slack, token));
        thread.start();
    }
}
