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
import com.github.seratch.jslack.api.methods.request.im.ImHistoryRequest;
import com.github.seratch.jslack.api.methods.request.im.ImOpenRequest;
import com.github.seratch.jslack.api.methods.request.users.UsersListRequest;
import com.github.seratch.jslack.api.methods.response.channels.ChannelsHistoryResponse;
import com.github.seratch.jslack.api.methods.response.chat.ChatPostMessageResponse;
import com.github.seratch.jslack.api.methods.response.im.ImHistoryResponse;
import com.github.seratch.jslack.api.methods.response.im.ImOpenResponse;
import com.github.seratch.jslack.api.model.Channel;
import com.github.seratch.jslack.api.model.User;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import pt.ipb.ssi.chatslack.gnupg.Openpgp;

/**
 *
 * @author Douglas Folletto
 */
public class Chat_2 extends javax.swing.JFrame {

    String botUserToken, token;
    Slack slack;
    int CanalAtual = 0;
    int usuarioAtual = 0;
    Map<String, String> usuarioMap = new HashMap<>();

    Openpgp gpg;

    DefaultListModel listModelCanais = new DefaultListModel();
    DefaultListModel listModelUsuarios = new DefaultListModel();
    ArrayList<Channel> canais = new ArrayList<Channel>();

    /**
     * Creates new form Chat
     *
     * @param botUserToken
     * @param token
     */
    public Chat_2(String botUserToken, String token) {
        initComponents();
        gpg = new Openpgp();

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
                setChatHistory();
            }

        });
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
            Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
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
            Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
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

        jMenuBar2 = new javax.swing.JMenuBar();
        jMenu3 = new javax.swing.JMenu();
        jMenu4 = new javax.swing.JMenu();
        txtMsgEnviar = new javax.swing.JTextField();
        btnEnviar = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        listCanais = new javax.swing.JList<>();
        jScrollPane3 = new javax.swing.JScrollPane();
        listDM = new javax.swing.JList<>();
        jCheckBoxEncrypt = new javax.swing.JCheckBox();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtMsgRecebida = new javax.swing.JTextArea();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenuItem5 = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenuItem2 = new javax.swing.JMenuItem();
        jMenuItem8 = new javax.swing.JMenuItem();
        jMenuItem3 = new javax.swing.JMenuItem();
        jMenuItem4 = new javax.swing.JMenuItem();
        jMenuItem6 = new javax.swing.JMenuItem();
        jMenu5 = new javax.swing.JMenu();
        jMenuItem7 = new javax.swing.JMenuItem();

        jMenu3.setText("File");
        jMenuBar2.add(jMenu3);

        jMenu4.setText("Edit");
        jMenuBar2.add(jMenu4);

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Chat");

        btnEnviar.setText("Enviar");
        btnEnviar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEnviarActionPerformed(evt);
            }
        });

        jLabel1.setText("Canais");

        jLabel2.setText("DM");

        listCanais.addPropertyChangeListener(new java.beans.PropertyChangeListener() {
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                listCanaisPropertyChange(evt);
            }
        });
        jScrollPane2.setViewportView(listCanais);

        jScrollPane3.setViewportView(listDM);

        jCheckBoxEncrypt.setText("Encrypt & Sign");

        txtMsgRecebida.setEditable(false);
        txtMsgRecebida.setColumns(20);
        txtMsgRecebida.setRows(5);
        jScrollPane1.setViewportView(txtMsgRecebida);

        jMenu1.setText("File");

        jMenuItem5.setText("Quit");
        jMenuItem5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem5ActionPerformed(evt);
            }
        });
        jMenu1.add(jMenuItem5);

        jMenuBar1.add(jMenu1);

        jMenu2.setText("Keys");

        jMenuItem1.setText("Add Public Key");
        jMenu2.add(jMenuItem1);

        jMenuItem2.setText("Search Public Keys");
        jMenu2.add(jMenuItem2);

        jMenuItem8.setText("Use my existing Key");
        jMenuItem8.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem8ActionPerformed(evt);
            }
        });
        jMenu2.add(jMenuItem8);

        jMenuItem3.setText("Generate Keys");
        jMenuItem3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem3ActionPerformed(evt);
            }
        });
        jMenu2.add(jMenuItem3);

        jMenuItem4.setText("Export Keys");
        jMenu2.add(jMenuItem4);

        jMenuItem6.setText("Test Generated Keys");
        jMenuItem6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem6ActionPerformed(evt);
            }
        });
        jMenu2.add(jMenuItem6);

        jMenuBar1.add(jMenu2);

        jMenu5.setText("User");

        jMenuItem7.setText("Add Public Key");
        jMenuItem7.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem7ActionPerformed(evt);
            }
        });
        jMenu5.add(jMenuItem7);

        jMenuBar1.add(jMenu5);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jCheckBoxEncrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 122, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jLabel1)
                            .addComponent(jLabel2)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 142, Short.MAX_VALUE)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(txtMsgEnviar, javax.swing.GroupLayout.PREFERRED_SIZE, 411, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnEnviar)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(jScrollPane1))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 75, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 107, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 137, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtMsgEnviar, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnEnviar, javax.swing.GroupLayout.Alignment.TRAILING))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jCheckBoxEncrypt)
                .addGap(12, 12, 12))
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    public void limpaCampo() {
        txtMsgEnviar.setText("");
    }

    public String getMensagem() {
        return txtMsgEnviar.getText();
    }

    private void btnEnviarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEnviarActionPerformed
        // Clique no botão de enviar
        if (listCanais.getSelectedIndex() != -1) {
            String channelID = canais.get(CanalAtual).getId();
            System.out.println("Channel ID: " + channelID);
            if (!txtMsgEnviar.getText().isEmpty()) {
                String mensagem = txtMsgEnviar.getText();
                try {
                    if (jCheckBoxEncrypt.isSelected()) {
                        SelectPublicKey_2 window = new SelectPublicKey_2(this, usuarioMap);
                        window.setVisible(true);

                    } else {
                        System.out.println(slack.methods().chatPostMessage(ChatPostMessageRequest.builder().asUser(false).text(mensagem).username("Bot com nick que eu quiser").token(token).channel(channelID).build()));
                        setChatHistory();
                        txtMsgEnviar.setText("");
                    }

                } catch (IOException | SlackApiException ex) {
                    Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        } else {
            if (!txtMsgEnviar.getText().isEmpty()) {
                String userName = listDM.getSelectedValue();
                System.out.println("userName " + userName + " ID " + usuarioMap.get(userName));
                String channel = getChannelByUser();
                String mensagem = txtMsgEnviar.getText();
                try {
                    if (jCheckBoxEncrypt.isSelected()) {
                        System.out.println("./public_keys/" + usuarioMap.get(userName) + ".asc");
                        if (new File("./public_keys/" + usuarioMap.get(userName) + ".asc").exists()) {
                            String msg_encrypt = Openpgp.encryptMessage(mensagem, "./public_keys/" + usuarioMap.get(userName) + ".asc", true, true);

                            System.out.println(slack.methods().chatPostMessage(
                                    ChatPostMessageRequest.builder()
                                            .asUser(false)
                                            .text(msg_encrypt)
                                            //.username("BotRandom")
                                            .token(token).channel(channel).build()));
                            setChatHistory();
                            txtMsgEnviar.setText("");
                        } else {
                            JOptionPane.showMessageDialog(this, "You dont have the public key of this user registered!");
                        }
                    } else {
                        ChatPostMessageResponse test = slack.methods().chatPostMessage(
                                ChatPostMessageRequest.builder()
                                        .text(mensagem)
                                        .token(token)
                                        .channel(channel)
                                        .build()
                        );
                        System.out.println("resposta da mensagem " + test);
                        setChatHistory();
                    }
                } catch (IOException | SlackApiException | PGPException | NoSuchProviderException ex) {
                    Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
                }
                txtMsgEnviar.setText("");

            }
        }
    }//GEN-LAST:event_btnEnviarActionPerformed

    private void listCanaisPropertyChange(java.beans.PropertyChangeEvent evt) {//GEN-FIRST:event_listCanaisPropertyChange

    }//GEN-LAST:event_listCanaisPropertyChange

    private void jMenuItem5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem5ActionPerformed
        System.exit(0);
    }//GEN-LAST:event_jMenuItem5ActionPerformed

    private void jMenuItem3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem3ActionPerformed
        String password = JOptionPane.showInputDialog(
                this,
                "Enter the secret code to your key",
                "Secret code needed",
                JOptionPane.WARNING_MESSAGE
        );
        String email = JOptionPane.showInputDialog(
                this,
                "Enter your e-mail:",
                "E-mail needed",
                JOptionPane.INFORMATION_MESSAGE
        );
        boolean ok = gpg.generate_KeyPair(password, email);
        if (ok) {
            JOptionPane.showMessageDialog(this, "Keys were generated and saved on the directory of this application!");
        }

    }//GEN-LAST:event_jMenuItem3ActionPerformed

    private void jMenuItem6ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem6ActionPerformed
        try {
            Security.addProvider(new BouncyCastleProvider());
            //encryptFile("arquivoCriptografado.txt", "arquivo.txt", "./dummy.asc", true, true);
            String mensagem = JOptionPane.showInputDialog(
                    this,
                    "Enter the message to be encrypted using your public key:",
                    "Message needed",
                    JOptionPane.WARNING_MESSAGE
            );
            String encriptada = gpg.encryptMessage(mensagem, "./publica.asc", true, true);
            JOptionPane.showMessageDialog(this, "Encrypted message:\n" + encriptada);
            String password = JOptionPane.showInputDialog(
                    this,
                    "Enter the secret code to your key",
                    "Secret code needed",
                    JOptionPane.WARNING_MESSAGE
            );
            String teste = Openpgp.decryptMessage(encriptada, "./privada.asc", password.toCharArray());
            if (teste != null) {
                JOptionPane.showMessageDialog(this, "Decrypted message: \n" + teste);
            } else {
                JOptionPane.showMessageDialog(this, "Key or password incorrect!");
            }
        } catch (IOException ex) {
            Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_jMenuItem6ActionPerformed

    private void jMenuItem7ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem7ActionPerformed
        UsersPublicKey window = new UsersPublicKey(usuarioMap);
        window.setVisible(true);
    }//GEN-LAST:event_jMenuItem7ActionPerformed

    private void jMenuItem8ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem8ActionPerformed
        String privateKey = JOptionPane.showInputDialog(
                this,
                "Insert your private key content:",
                "Insert the private key",
                JOptionPane.WARNING_MESSAGE
        );
        try (PrintWriter saida = new PrintWriter("./privada.asc")) {
            saida.println(privateKey);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
        }
        JOptionPane.showMessageDialog(this, "Private key was saved on application directory (privada.asc)!");

    }//GEN-LAST:event_jMenuItem8ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnEnviar;
    private javax.swing.JCheckBox jCheckBoxEncrypt;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenu jMenu3;
    private javax.swing.JMenu jMenu4;
    private javax.swing.JMenu jMenu5;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuBar jMenuBar2;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JMenuItem jMenuItem3;
    private javax.swing.JMenuItem jMenuItem4;
    private javax.swing.JMenuItem jMenuItem5;
    private javax.swing.JMenuItem jMenuItem6;
    private javax.swing.JMenuItem jMenuItem7;
    private javax.swing.JMenuItem jMenuItem8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JList<String> listCanais;
    private javax.swing.JList<String> listDM;
    private javax.swing.JTextField txtMsgEnviar;
    private javax.swing.JTextArea txtMsgRecebida;
    // End of variables declaration//GEN-END:variables

    public void setChatHistory() {
        if (listCanais.getSelectedIndex() != -1) {
            try {
                txtMsgRecebida.setText("");
                String channelID = canais.get(CanalAtual).getId();
                System.out.println(slack.methods().channelsHistory(ChannelsHistoryRequest.builder().token(botUserToken).build()).getMessages());
                ChannelsHistoryResponse history = slack.methods().channelsHistory(ChannelsHistoryRequest.builder()
                        .token(token)
                        .channel(channelID)
                        .count(5)
                        .build());
                System.out.println(channelID);
                System.out.println(history);
                String password = null;
                if (history.getMessages() != null) {
                    for (int i = history.getMessages().size() - 1; i >= 0; i--) {
                        if (history.getMessages().get(i).getText().contains("-----BEGIN PGP MESSAGE-----")) {
                            if (password == null) {
                                password = JOptionPane.showInputDialog(
                                        this,
                                        "There is a encrypted message, we can try to decrypt, please insert your private key password:",
                                        "Secret code needed",
                                        JOptionPane.WARNING_MESSAGE
                                );
                            }
                            String result = Openpgp.decryptMessage(history.getMessages().get(i).getText(), "./privada.asc", password.toCharArray());
                            if (result != null) {
                                txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": " + result);
                            } else {
                                txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": Sended an encrypted message"  + "\n");
                            }
                        } else {
                            if (history.getMessages().get(i).getUsername() != null) {
                                txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": " + history.getMessages().get(i).getText() + "\n");
                            } else if (history.getMessages().get(i).getText().contains("<@")) {
                                txtMsgRecebida.append(/*name */" " + history.getMessages().get(i).getText() + "\n");

                            } else {
                                txtMsgRecebida.append(history.getMessages().get(i).getText() + "\n");
                            }
                        }
                    }
                }
            } catch (IOException | SlackApiException ex) {
                Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchProviderException ex) {
                Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            //DM está selecionado

            if (listDM.getSelectedIndex() != -1) {
                try {
                    txtMsgRecebida.setText("");
                    String userID = getUserIDbyList();
                    ImOpenResponse canal = slack.methods().imOpen(ImOpenRequest.builder().user(userID).token(token).build());
                    if (canal.getChannel().getId() != null) {
                        ImHistoryResponse history = slack.methods().imHistory(
                                ImHistoryRequest.builder()
                                        .channel(canal.getChannel().getId())
                                        .token(token)
                                        .count(1000)
                                        .build());
                        String password = null;
                        //System.out.println("history " + history);
                        if (history.getMessages() != null) {
                            for (int i = history.getMessages().size() - 1; i >= 0; i--) {
                                if (history.getMessages().get(i).getText().contains("-----BEGIN PGP MESSAGE-----")) {
                                    if (password == null) {
                                        password = JOptionPane.showInputDialog(
                                                this,
                                                "There is a encrypted message, we can try to decrypt, please insert your private key password:",
                                                "Secret code needed",
                                                JOptionPane.WARNING_MESSAGE
                                        );
                                    }
                                    String result = Openpgp.decryptMessage(history.getMessages().get(i).getText(), "./privada.asc", password.toCharArray());
                                    System.out.println("result "+  result);
                                    if (result != null) {
                                        System.out.println("Aqui 1");
                                        txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": " + result);
                                    } else {
                                        System.out.println("Aqui 2");
                                        txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": Sended an encrypted message"  + "\n");
                                    }
                                } else {
                                    if (history.getMessages().get(i).getUsername() != null) {
                                        txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": " + history.getMessages().get(i).getText() + "\n");
                                    } else if (history.getMessages().get(i).getText().contains("<@")) {
                                        txtMsgRecebida.append(/*name */" " + history.getMessages().get(i).getText() + "\n");
                                    } else {
                                        txtMsgRecebida.append(history.getMessages().get(i).getText() + "\n");
                                    }
                                }
                            }
                        }
                    }
                } catch (IOException | SlackApiException ex) {
                    Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
    }

    private String getChannelByUser() {
        try {
            ImOpenResponse canal = slack.methods().imOpen(ImOpenRequest.builder().user(getUserIDbyList()).token(token).build());
            return canal.getChannel().getId();
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(Chat_2.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }

    private String getUserIDbyList() {
        return usuarioMap.get(listDM.getSelectedValue());
    }

}
