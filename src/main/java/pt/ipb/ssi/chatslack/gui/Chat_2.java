/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack.gui;

import com.github.seratch.jslack.api.methods.response.channels.ChannelsHistoryResponse;
import com.github.seratch.jslack.api.methods.response.im.ImHistoryResponse;
import com.github.seratch.jslack.api.model.Channel;
import com.github.seratch.jslack.api.model.User;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import pt.ipb.ssi.chatslack.gnupg.Openpgp;
import pt.ipb.ssi.chatslack.model.MessageListModel;
import pt.ipb.ssi.chatslack.renderer.MessageListRenderer;
import pt.ipb.ssi.chatslack.slack.SlackImpl;

/**
 *
 * @author Douglas Folletto
 */
public class Chat_2 extends javax.swing.JFrame {

    SlackImpl slackImpl;

    String botUserToken, token;
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

        this.slackImpl = new SlackImpl(botUserToken, token);

        this.botUserToken = botUserToken;
        this.token = token;
        listCanais.setModel(listModelCanais);
        listDM.setModel(listModelUsuarios);
        //slackImpl.downloadFile("FAY298DRB");

//System.out.println("Bot Information  :  "
        //        + slack.methods().botsInfo(BotsInfoRequest.builder().token(botUserToken).build()));
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
                //System.out.println("userName " + userName + " ID " + usuarioMap.get(userName));
                setChatHistory();
            }

        });

        listMessages.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                System.out.println("listMe " + listMessages.getSelectedIndex());
            }

        });

        listMessages.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent me) {
                //Verificando se o botão direito do mouse foi clicado
                MessageListModel value = listMessages.getModel().getElementAt(listMessages.locationToIndex(me.getPoint()));
                System.out.println("Message " + value.toString());
                if ((me.getModifiers() & MouseEvent.BUTTON3_MASK) != 0) {
                    JPopupMenu jPopupMenu = new JPopupMenu();

                    //Verifica se a mensagem tem Arquivo para download;
                    if (value.getMessageSlack().getFile() != null) {
                        JMenuItem menuDownload = new JMenuItem("Download");
                        jPopupMenu.add(menuDownload);
                        menuDownload.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent e) {
                                //Pega o ID para o Download:
                                String idFile = value.getMessageSlack().getFile().getId();
                                boolean downloadFile = slackImpl.downloadFile(idFile, Chat_2.this);
                                if (downloadFile) {
                                    JOptionPane.showMessageDialog(null, "Arquivo Baixado");
                                } else {
                                    JOptionPane.showMessageDialog(null, "Arquivo Não Baixado");
                                }
                                System.out.println("Clicked ");
                                System.out.println(value.getMessage());
                            }
                        });
                    }

                    JMenuItem menuItem = new JMenuItem("Menu Item");
                    jPopupMenu.add(menuItem);
                    menuItem.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            System.out.println("Clicked ");

                        }
                    });

                    jPopupMenu.show(listMessages, me.getX(), me.getY());
                }
            }
        });

    }

    private void setListChannel() {
        listModelCanais.removeAllElements();
        canais.removeAll(canais);
        List<Channel> listChannels = slackImpl.getListChannels();
        for (Channel channel : listChannels) {
            canais.add(channel);
            listModelCanais.addElement(channel.getName());
        }
    }

    private void setListUsers() {
        List<User> users = slackImpl.getListUsers();
        for (User user : users) {
            if (!user.isBot()) {
                listModelUsuarios.addElement(user.getName());
                usuarioMap.put(user.getName(), user.getId());
            }
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
        jScrollPane4 = new javax.swing.JScrollPane();
        jList1 = new javax.swing.JList<>();
        jFileChooserMessage = new javax.swing.JFileChooser();
        txtMsgEnviar = new javax.swing.JTextField();
        btnEnviar = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        listCanais = new javax.swing.JList<>();
        jScrollPane3 = new javax.swing.JScrollPane();
        listDM = new javax.swing.JList<>();
        jCheckBoxEncrypt = new javax.swing.JCheckBox();
        jScrollPane5 = new javax.swing.JScrollPane();
        listMessages = new javax.swing.JList<>();
        jButton1 = new javax.swing.JButton();
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
        jMenuItem9 = new javax.swing.JMenuItem();
        jMenu5 = new javax.swing.JMenu();
        jMenuItem7 = new javax.swing.JMenuItem();

        jMenu3.setText("File");
        jMenuBar2.add(jMenu3);

        jMenu4.setText("Edit");
        jMenuBar2.add(jMenu4);

        jList1.setModel(new javax.swing.AbstractListModel<String>() {
            String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
            public int getSize() { return strings.length; }
            public String getElementAt(int i) { return strings[i]; }
        });
        jScrollPane4.setViewportView(jList1);

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

        listMessages.setFont(new java.awt.Font("Garamond", 0, 18)); // NOI18N
        jScrollPane5.setViewportView(listMessages);

        jButton1.setText("Arquivo");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

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

        jMenuItem9.setText("User List Key");
        jMenuItem9.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem9ActionPerformed(evt);
            }
        });
        jMenu2.add(jMenuItem9);

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
                    .addComponent(jCheckBoxEncrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 122, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jLabel1)
                            .addComponent(jLabel2)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 142, Short.MAX_VALUE)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(txtMsgEnviar, javax.swing.GroupLayout.PREFERRED_SIZE, 598, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnEnviar)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jButton1))
                            .addComponent(jScrollPane5))))
                .addContainerGap(16, Short.MAX_VALUE))
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
                        .addGap(0, 141, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(3, 3, 3)
                        .addComponent(jScrollPane5)
                        .addGap(9, 9, 9)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(txtMsgEnviar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnEnviar)
                            .addComponent(jButton1))))
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
//            System.out.println("Channel ID: " + channelID);
            if (!txtMsgEnviar.getText().isEmpty()) {
                String mensagem = txtMsgEnviar.getText();
                if (jCheckBoxEncrypt.isSelected()) {
                    SelectPublicKey_2 window = new SelectPublicKey_2(this, usuarioMap);
                    window.setVisible(true);

                } else {
                    slackImpl.sendMessage(channelID, mensagem);
                    setChatHistory();
                    txtMsgEnviar.setText("");
                }

            }
        } else {
            if (!txtMsgEnviar.getText().isEmpty()) {
                String userName = listDM.getSelectedValue();
//                System.out.println("userName " + userName + " ID " + usuarioMap.get(userName));
                String channel = slackImpl.getChannelByUser(getUserIDbyList());
                String mensagem = txtMsgEnviar.getText();
                try {
                    if (jCheckBoxEncrypt.isSelected()) {
//                        System.out.println("./public_keys/" + usuarioMap.get(userName) + ".asc");
                        if (new File("./public_keys/" + usuarioMap.get(userName) + ".asc").exists()) {
                            String msg_encrypt = Openpgp.encryptMessage(mensagem, "./public_keys/" + usuarioMap.get(userName) + ".asc", true, true);

                            boolean sendMessage = slackImpl.sendMessage(channel, msg_encrypt);
                            if (sendMessage) {
                                setChatHistory();
                                txtMsgEnviar.setText("");
                            } else {
                                JOptionPane.showMessageDialog(null, "Erro ao enviar a Mensagem!");
                            }
                        } else {
                            JOptionPane.showMessageDialog(this, "You dont have the public key of this user registered!");
                        }
                    } else {
                        boolean sendMessage = slackImpl.sendMessage(channel, mensagem);
                        if (sendMessage) {
                            setChatHistory();
                            txtMsgEnviar.setText("");
                        } else {
                            JOptionPane.showMessageDialog(null, "Erro ao enviar a Mensagem!");
                        }
                    }
                } catch (IOException | PGPException | NoSuchProviderException ex) {
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

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        //Abrir para selecionar a imagem
        int returnVal = jFileChooserMessage.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            // Chamar a tela que fara o upload da imagem
            File file = jFileChooserMessage.getSelectedFile();
            System.out.println("File" + file);
            // What to do with the file, e.g. display it in a TextArea
            FileUpload fileUpload = new FileUpload(slackImpl, token, file, this);
            fileUpload.setVisible(true);
        } else {
            System.out.println("File access cancelled by user.");
        }


    }//GEN-LAST:event_jButton1ActionPerformed

    private void jMenuItem9ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem9ActionPerformed
        // Abre a lista de usuarios com chaves
    }//GEN-LAST:event_jMenuItem9ActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnEnviar;
    private javax.swing.JButton jButton1;
    private javax.swing.JCheckBox jCheckBoxEncrypt;
    private javax.swing.JFileChooser jFileChooserMessage;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JList<String> jList1;
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
    private javax.swing.JMenuItem jMenuItem9;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JList<String> listCanais;
    private javax.swing.JList<String> listDM;
    private javax.swing.JList<MessageListModel> listMessages;
    private javax.swing.JTextField txtMsgEnviar;
    // End of variables declaration//GEN-END:variables

    public void setChatHistory() {
        // Cria o modelo e limpa a lista exibida
        DefaultListModel<MessageListModel> listMessage = new DefaultListModel<>();
        listMessages.setModel(listMessage);
        listMessages.setCellRenderer(new MessageListRenderer());
        if (listCanais.getSelectedIndex() != -1) {
            try {
                String channelID = canais.get(CanalAtual).getId();
//                System.out.println(slack.methods().channelsHistory(ChannelsHistoryRequest.builder().token(botUserToken).build()).getMessages());
                ChannelsHistoryResponse history = slackImpl.getChannelHistory(channelID);
                String password = null;
                if (history.getMessages() != null) {
                    for (int i = history.getMessages().size() - 1; i >= 0; i--) {
                        String message = history.getMessages().get(i).getText();
                        String userName = history.getMessages().get(i).getUsername();
                        String date = history.getMessages().get(i).getTs();
                        SimpleDateFormat inputFormat = new SimpleDateFormat("dd/MM/yyyy");
                        if (userName == null) {
                            userName = history.getMessages().get(i).getUser();
                        }
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
                            MessageListModel msg = new MessageListModel(userName, result, history.getMessages().get(i));
                            listMessage.addElement(msg);

                        } else {
                            MessageListModel msg = new MessageListModel(userName, message, history.getMessages().get(i));
                            listMessage.addElement(msg);

                        }
                    }
                }
            } catch (IOException | NoSuchProviderException ex) {
                Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            //DM está selecionado

            if (listDM.getSelectedIndex() != -1) {
                try {
                    String userID = getUserIDbyList();
                    ImHistoryResponse history = slackImpl.getChannelDM(userID);
                    String password = null;
                    System.out.println("history.getMessages() " + history);
                    System.out.println("Fim \n\n\n\n) ");
                    if (history.getMessages() != null) {
                        for (int i = history.getMessages().size() - 1; i >= 0; i--) {
                            //System.out.println("\n\n\n" + " History " + history + "\n\n\n");

                            String message = history.getMessages().get(i).getText();
                            String userName = history.getMessages().get(i).getUsername();
                            if (userName == null) {
                                userName = history.getMessages().get(i).getUser();
                            }
                            if (history.getMessages().get(i).getText().contains("-----BEGIN PGP MESSAGE-----")) {
                                if (password == null) {
                                    password = JOptionPane.showInputDialog(
                                            this,
                                            "There is a encrypted message, we can try to decrypt, please insert your private key password:",
                                            "Secret code needed",
                                            JOptionPane.WARNING_MESSAGE
                                    );
                                }
                                if (password != null) {
                                    String result = Openpgp.decryptMessage(history.getMessages().get(i).getText(), "./privada.asc", password.toCharArray());
                                    MessageListModel msg = new MessageListModel(userName, result, history.getMessages().get(i));
                                    listMessage.addElement(msg);
                                } else {
                                    MessageListModel msg = new MessageListModel(userName, message, history.getMessages().get(i));
                                    listMessage.addElement(msg);
                                }
                            } else {
                                MessageListModel msg = new MessageListModel(userName, message, history.getMessages().get(i));
                                listMessage.addElement(msg);
                            }
                        }
                    }

                } catch (IOException | NoSuchProviderException ex) {
                    Logger.getLogger(Chat_2.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        listMessages.setModel(listMessage);
    }

    private String getUserIDbyList() {
        return usuarioMap.get(listDM.getSelectedValue());
    }

}
