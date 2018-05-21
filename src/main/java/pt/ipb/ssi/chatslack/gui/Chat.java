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
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.swing.DefaultListModel;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import pt.ipb.ssi.chatslack.rtm.RTMRunnable;
import static sun.security.x509.CertificateAlgorithmId.ALGORITHM;

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
        Security.addProvider(new BouncyCastleProvider());
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
        new File("./public_keys").mkdirs();

        /*SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        if (listCanais.getSelectedIndex() != -1) {
                            setChatHistory();
                        } else {
                            String userName = listDM.getSelectedValue();
                            setDMChatHistory(usuarioMap.get(userName));
                        }
                        Thread.sleep(3000);
                    } catch (InterruptedException ex) {
                        Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

            }
        });*/
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
            String password=null;
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
                        String result = decryptMessage(history.getMessages().get(i).getText(), "./privada.asc", password.toCharArray());
                        if (result != null) {
                            txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": " + result);
                        } else {
                            txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": Sended an encrypted message");
                        }
                    } else {
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
                // }
            }
        } catch (IOException | SlackApiException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
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

        jMenuBar2 = new javax.swing.JMenuBar();
        jMenu3 = new javax.swing.JMenu();
        jMenu4 = new javax.swing.JMenu();
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
        jCheckBoxEncrypt = new javax.swing.JCheckBox();
        jCheckBoxSign = new javax.swing.JCheckBox();
        jScrollPane1 = new javax.swing.JScrollPane();
        txtMsgRecebida = new javax.swing.JTextArea();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenuItem5 = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenuItem2 = new javax.swing.JMenuItem();
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

        jLabel3.setText("Apps");

        listCanais.addPropertyChangeListener(new java.beans.PropertyChangeListener() {
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                listCanaisPropertyChange(evt);
            }
        });
        jScrollPane2.setViewportView(listCanais);

        jScrollPane3.setViewportView(listDM);

        jScrollPane4.setViewportView(listApps);

        jCheckBoxEncrypt.setText("Encrypt");

        jCheckBoxSign.setText("Sign");

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
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 142, Short.MAX_VALUE)
                            .addComponent(jLabel1)
                            .addComponent(jLabel2)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                            .addComponent(jLabel3))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(txtMsgEnviar, javax.swing.GroupLayout.PREFERRED_SIZE, 411, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(btnEnviar)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(jScrollPane1)))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jCheckBoxSign)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jCheckBoxEncrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 70, javax.swing.GroupLayout.PREFERRED_SIZE)))
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
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 320, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(txtMsgEnviar, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnEnviar, javax.swing.GroupLayout.Alignment.TRAILING))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jCheckBoxEncrypt)
                    .addComponent(jCheckBoxSign))
                .addContainerGap())
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
                        SelectPublicKey window = new SelectPublicKey(this, usuarioMap);
                        window.setVisible(true);

                    } else {
                        System.out.println(slack.methods().chatPostMessage(ChatPostMessageRequest.builder().asUser(false).text(mensagem).username("Bot com nick que eu quiser").token(token).channel(channelID).build()));
                        setChatHistory();
                        txtMsgEnviar.setText("");
                    }

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
                    if (jCheckBoxEncrypt.isSelected()) {
                        System.out.println("./public_keys/" + usuarioMap.get(userName) + ".asc");
                        if (new File("./public_keys/" + usuarioMap.get(userName) + ".asc").exists()) {
                            System.out.println(slack.methods().chatPostMessage(ChatPostMessageRequest.builder().asUser(false).text(encryptMessage(mensagem, "./public_keys/" + usuarioMap.get(userName) + ".asc", true, true)).username("BotRandom").token(token).channel(channel).build()));
                            setChatHistory();
                            txtMsgEnviar.setText("");
                        } else {
                            JOptionPane.showMessageDialog(this, "You dont have the public key of this user registered!");
                        }
                    } else {
                        slack.methods().chatPostMessage(ChatPostMessageRequest.builder().asUser(true).text(mensagem).username("TesteBotSDASDDAS").iconEmoji(":chart_with_upwards_trend:").asUser(true).token(botUserToken).channel(channel).build());
                        setDMChatHistory(usuarioMap.get(userName).toString());
                        txtMsgEnviar.setText("");
                    }
                } catch (IOException ex) {
                    Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
                } catch (SlackApiException ex) {
                    Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
                } catch (PGPException ex) {
                    Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
                }

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

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", "BC");

            kpg.initialize(1024);

            KeyPair kp = kpg.generateKeyPair();

            FileOutputStream out1 = new FileOutputStream("privada.asc");
            FileOutputStream out2 = new FileOutputStream("publica.asc");

            exportKeyPair(out1, out2, kp, email, password.toCharArray(), true);
            JOptionPane.showMessageDialog(this, "Keys were generated and saved on the directory of this application!");

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        }


    }//GEN-LAST:event_jMenuItem3ActionPerformed

    private static void exportKeyPair(
            OutputStream secretOut,
            OutputStream publicOut,
            KeyPair pair,
            String identity,
            char[] passPhrase,
            boolean armor)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
        if (armor) {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
        PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

        secretKey.encode(secretOut);

        secretOut.close();

        if (armor) {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        PGPPublicKey key = secretKey.getPublicKey();

        key.encode(publicOut);

        publicOut.close();
    }

    private static void decryptFile(
            String inputFileName,
            String keyFileName,
            char[] passwd,
            String defaultFileName)
            throws IOException, NoSuchProviderException {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        decryptFile(in, keyIn, passwd, defaultFileName);
        keyIn.close();
        in.close();
    }

    /**
     * decrypt the passed in message stream
     */
    private static void decryptFile(
            InputStream in,
            InputStream keyIn,
            char[] passwd,
            String defaultFileName)
            throws IOException, NoSuchProviderException {
        in = PGPUtil.getDecoderStream(in);

        try {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            //
            // find the secret key
            //
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();

                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;

                String outFileName = ld.getFileName();
                if (outFileName.length() == 0) {
                    outFileName = defaultFileName;
                }

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outFileName));

                Streams.pipeAll(unc, fOut);

                fOut.close();
            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    System.err.println("message failed integrity check");
                } else {
                    System.err.println("message integrity check passed");
                }
            } else {
                System.err.println("no message integrity check");
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    private static void encryptFile(
            String outputFileName,
            String inputFileName,
            String encKeyFileName,
            boolean armor,
            boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException, PGPException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        PGPPublicKey encKey = readPublicKey(encKeyFileName);
        encryptFile(out, inputFileName, encKey, armor, withIntegrityCheck);
        out.close();
    }

    static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    /**
     * A simple routine that opens a key ring file and loads the first available
     * key suitable for encryption.
     *
     * @param input data stream containing the public key data
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    static PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn);
        keyIn.close();
        return secKey;
    }

    /**
     * A simple routine that opens a key ring file and loads the first available
     * key suitable for signature generation.
     *
     * @param input stream to read the secret key ring collection from.
     * @return a secret key.
     * @throws IOException on a problem with using the input stream.
     * @throws PGPException if there is an issue parsing the input stream.
     */
    static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();

                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    static byte[] compressFile(String fileName, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
                new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

    private static OutputStream convertStringtoStream(String string) throws IOException {
        byte[] stringByte = string.getBytes();
        ByteArrayOutputStream bos = new ByteArrayOutputStream(string.length());
        bos.write(stringByte);
        return bos;
    }

    static String readFile(String path, Charset encoding)
            throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }

    private static String decryptMessage(
            String mensagemEncryptada,
            String keyFileName,
            char[] passwd)
            throws IOException, NoSuchProviderException {
        try (PrintWriter saida = new PrintWriter("./tmp.txt")) {
            saida.println(mensagemEncryptada);
        }
        InputStream in = new BufferedInputStream(new FileInputStream("./tmp.txt"));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        decryptFile(in, keyIn, passwd, "./out.txt");
        keyIn.close();
        in.close();
        String result = readFile("./tmp.txt", Charset.defaultCharset());
        new File("./out.txt").delete();
        new File("./tmp.txt").delete();
        return result;
    }

    public static String encryptMessage(String mensagem, String nomeChave, boolean armor, boolean withIntegrityCheck) throws IOException, PGPException, NoSuchProviderException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream("./out.txt"));
        try (PrintWriter saida = new PrintWriter("./tmp.txt")) {
            saida.println(mensagem);
        }

        PGPPublicKey encKey = readPublicKey(nomeChave);
        encryptFile(out, "./tmp.txt", encKey, armor, withIntegrityCheck);
        out.close();
        String result = readFile("./out.txt", Charset.defaultCharset());
        new File("./out.txt").delete();
        new File("./tmp.txt").delete();
        System.out.println(result);
        return result;
    }

    private static void encryptFile(
            OutputStream out,
            String fileName,
            PGPPublicKey encKey,
            boolean armor,
            boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        try {
            byte[] bytes = compressFile(fileName, CompressionAlgorithmTags.ZIP);

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

            OutputStream cOut = encGen.open(out, bytes.length);

            cOut.write(bytes);
            cOut.close();

            if (armor) {
                out.close();
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }


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
            String encriptada = encryptMessage(mensagem, "./publica.asc", true, true);
            JOptionPane.showMessageDialog(this, "Encrypted message:\n" + encriptada);
            String password = JOptionPane.showInputDialog(
                    this,
                    "Enter the secret code to your key",
                    "Secret code needed",
                    JOptionPane.WARNING_MESSAGE
            );
            String teste = decryptMessage(encriptada, "./privada.asc", password.toCharArray());
            if (teste != null) {
                JOptionPane.showMessageDialog(this, "Decrypted message: \n" + teste);
            } else {
                JOptionPane.showMessageDialog(this, "Key or password incorrect!");
            }
        } catch (IOException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        }

    }//GEN-LAST:event_jMenuItem6ActionPerformed

    private void jMenuItem7ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem7ActionPerformed
        UsersPublicKey window = new UsersPublicKey(usuarioMap);
        window.setVisible(true);
    }//GEN-LAST:event_jMenuItem7ActionPerformed

    public PGPPublicKey getPublicKey(String dir) throws IOException, PGPException {

        PGPPublicKey key = null;
        BufferedReader br = new BufferedReader(new FileReader(dir));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            String everything = sb.toString();
            System.out.println(everything);
            InputStream in = new ByteArrayInputStream(everything.getBytes());
            in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

            JcaPGPPublicKeyRingCollection pgpPub = new JcaPGPPublicKeyRingCollection(in);
            in.close();

            Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
            while (key == null && rIt.hasNext()) {
                PGPPublicKeyRing kRing = rIt.next();
                Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
                while (key == null && kIt.hasNext()) {
                    PGPPublicKey k = kIt.next();

                    if (k.isEncryptionKey()) {
                        key = k;
                    }
                }
            }
        } finally {
            br.close();
        }

        return key;
    }

    public static boolean
            verifySignedObject(PGPPublicKey verifyingKey,
                    byte[] pgpSignedData)
            throws
            PGPException, IOException {
        JcaPGPObjectFactory pgpFact
                = new JcaPGPObjectFactory(pgpSignedData);
        PGPOnePassSignatureList onePassList = (PGPOnePassSignatureList) pgpFact.nextObject();
        PGPOnePassSignature ops = onePassList.get(
                0
        );
        PGPLiteralData literalData = (PGPLiteralData) pgpFact.nextObject();
        InputStream dIn = literalData.getInputStream();
        ops.init(
                new JcaPGPContentVerifierBuilderProvider().setProvider(
                        "BCFIPS"
                ), verifyingKey);
        int ch;
        while ((ch = dIn.read())
                >= 0) {
            ops.update((byte) ch);
        }
        PGPSignatureList sigList = (PGPSignatureList) pgpFact.nextObject();
        PGPSignature sig = sigList.get(
                0
        );
        return ops.verify(sig);
    }

    public static byte[] createSignedObject(int signingAlg, PGPPrivateKey signingKey,
            byte[] data)
            throws
            PGPException, IOException {
        ByteArrayOutputStream bOut
                = new ByteArrayOutputStream();
        BCPGOutputStream bcOut
                = new BCPGOutputStream(bOut);
        PGPSignatureGenerator sGen
                = new PGPSignatureGenerator(
                        new JcaPGPContentSignerBuilder(
                                signingAlg,
                                PGPUtil.SHA384
                        ).setProvider(
                                "BCFIPS"
                        ));
        sGen.init(PGPSignature.BINARY_DOCUMENT,
                signingKey);
        sGen.generateOnePassVersion(
                false
        ).encode(bcOut);
        PGPLiteralDataGenerator lGen
                = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(
                bcOut,
                PGPLiteralData.BINARY,
                "_CONSOLE",
                data.length,
                new Date());
        for (int i
                = 0; i != data.length; i++) {
            lOut.write(data[i]);
            sGen.update(data[i]);
        }
        lGen.close();
        sGen.generate().encode(bcOut);
        return bOut.toByteArray();
    }

    public static byte[] encrypt(byte[] text, PublicKey key) throws Exception {
        byte[] cipherText = null;
        //
        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text);
        return cipherText;
    }

    /**
     * Encrypt a text using public key. The result is enctypted BASE64 encoded
     * text
     *
     * @param text The original unencrypted text
     * @param key The public key
     * @return Encrypted text encoded as BASE64
     * @throws java.lang.Exception
     */
    public static String encrypt(String text, PublicKey key) throws Exception {
        String encryptedText;
        byte[] cipherText = encrypt(text.getBytes("UTF8"), key);
        encryptedText = encodeBASE64(cipherText);
        return encryptedText;
    }

    public static byte[] decrypt(byte[] text, PrivateKey key) throws Exception {
        byte[] dectyptedText = null;
        // decrypt the text using the private key
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        dectyptedText = cipher.doFinal(text);
        return dectyptedText;

    }

    /**
     * Decrypt BASE64 encoded text using private key
     *
     * @param text The encrypted text, encoded as BASE64
     * @param key The private key
     * @return The unencrypted text encoded as UTF8
     * @throws java.lang.Exception
     */
    public static String decrypt(String text, PrivateKey key) throws Exception {
        String result;
        // decrypt the text using the private key
        byte[] dectyptedText = decrypt(decodeBASE64(text), key);
        result = new String(dectyptedText, "UTF8");
        return result;

    }

    /**
     * Convert a Key to string encoded as BASE64
     *
     * @param key The key (private or public)
     * @return A string representation of the key
     */
    public static String getKeyAsString(Key key) {
        // Get the bytes of the key
        byte[] keyBytes = key.getEncoded();
        return encodeBASE64(keyBytes);
    }

    /**
     * Generates Private Key from BASE64 encoded string
     *
     * @param key BASE64 encoded string which represents the key
     * @return The PrivateKey
     * @throws java.lang.Exception
     */
    public static PrivateKey getPrivateKeyFromString(String key) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodeBASE64(key));
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        return privateKey;
    }

    /**
     * Generates Public Key from BASE64 encoded string
     *
     * @param key BASE64 encoded string which represents the key
     * @return The PublicKey
     * @throws java.lang.Exception
     */
    public static PublicKey getPublicKeyFromString(String key) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodeBASE64(key));
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return publicKey;
    }

    /**
     * Decode BASE64 encoded string to bytes array
     *
     * @param text The string
     * @return Bytes array
     * @throws IOException
     */
    private static byte[] decodeBASE64(String text) throws IOException {
        // BASE64Decoder b64 = new BASE64Decoder();
        // return b64.decodeBuffer(text);
        return Base64.getDecoder().decode(text);
    }

    private static String encodeBASE64(byte[] bytes) {
        try {
            // BASE64Encoder b64 = new BASE64Encoder();
            // return b64.encode(bytes, false);
            return new String(Base64.getEncoder().encode(bytes), "UTF8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }

    /**
     * Decode BASE64 encoded string to bytes array
     *
     * @param text The string
     * @return Bytes array
     * @throws IOException
     */
    /**
     * Encrypt file using 1024 RSA encryption
     *
     * @param srcFileName Source file name
     * @param destFileName Destination file name
     * @param key The key. For encryption this is the Private Key and for
     * decryption this is the public key
     * @param cipherMode Cipher Mode
     * @throws Exception
     */
    /**
     * Decrypt file using 1024 RSA encryption
     *
     * @param srcFileName Source file name
     * @param destFileName Destination file name
     * @param key The key. For encryption this is the Private Key and for
     * decryption this is the public key
     * @param cipherMode Cipher Mode
     * @throws Exception
     */
    /**
     * Encrypt and Decrypt files using 1024 RSA encryption
     *
     * @param srcFileName Source file name
     * @param destFileName Destination file name
     * @param key The key. For encryption this is the Private Key and for
     * decryption this is the public key
     * @param cipherMode Cipher Mode
     * @throws Exception
     */
    public static byte[] copyBytes(byte[] arr, int length) {
        byte[] newArr = null;
        if (arr.length == length) {
            newArr = arr;
        } else {
            newArr = new byte[length];
            for (int i = 0; i < length; i++) {
                newArr[i] = (byte) arr[i];
            }
        }
        return newArr;
    }

    private static byte[] compress(byte[] clearData, String fileName, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        OutputStream cos = comData.open(bOut); // open it with the final destination

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        // we want to generate compressed data. This might be a user option later,
        // in which case we would pass in bOut.
        OutputStream pOut = lData.open(cos, // the compressed output stream
                PGPLiteralData.BINARY,
                fileName, // "filename" to store
                clearData.length, // length of clear data
                new Date() // current time
        );

        pOut.write(clearData);
        pOut.close();

        comData.close();

        return bOut.toByteArray();
    }

    public static byte[] createRsaEncryptedObject(PGPPublicKey encryptionKey,
            byte[] data)
            throws
            PGPException, IOException {
        ByteArrayOutputStream bOut
                = new ByteArrayOutputStream();
        PGPLiteralDataGenerator lData
                = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(bOut,
                PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE,
                data.length,
                new Date());
        pOut.write(data);
        pOut.close();
        byte[] plainText = bOut.toByteArray();
        ByteArrayOutputStream encOut
                = new ByteArrayOutputStream();
        PGPEncryptedDataGenerator encGen
                = new PGPEncryptedDataGenerator(
                        new JcePGPDataEncryptorBuilder(
                                SymmetricKeyAlgorithmTags.AES_256
                        )
                                .setWithIntegrityPacket(
                                        true
                                )
                                .setSecureRandom(
                                        new SecureRandom())
                                .setProvider(
                                        "BCFIPS"
                                ));
        encGen.addMethod(
                new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey)
                        .setProvider(
                                "BCFIPS"
                        ));
        OutputStream cOut = encGen.open(encOut, plainText.length
        );
        cOut.write(plainText);
        cOut.close();
        return encOut.toByteArray();
    }

    public static byte[] extractRsaEncryptedObject(PGPPrivateKey privateKey,
            byte[] pgpEncryptedData)
            throws
            PGPException, IOException {
        PGPObjectFactory pgpFact
                = new JcaPGPObjectFactory(pgpEncryptedData);
        PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();
// note: we can only do this because we know we match the first encrypted data object
        PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.get(
                0
        );
        PublicKeyDataDecryptorFactory dataDecryptorFactory
                = new JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider(
                                "BCFIPS"
                        ).build(privateKey);
        InputStream clear = encData.getDataStream(dataDecryptorFactory);
        byte[] literalData = Streams.
                readAll(clear);
        if (encData.verify()) {
            PGPObjectFactory litFact
                    = new JcaPGPObjectFactory(literalData);
            PGPLiteralData litData = (PGPLiteralData) litFact.nextObject();
            byte[] data = Streams.
                    readAll(litData.getInputStream());
            return data;
        }
        throw new IllegalStateException(
                "modification check failed"
        );
    }

    public final static PGPKeyRingGenerator generateKeyRingGenerator(String id, char[] pass) throws Exception {
        return generateKeyRingGenerator(id, pass, 0xc0);
    }

    public final static PGPKeyRingGenerator generateKeyRingGenerator(String id, char[] pass, int s2kcount) throws Exception {
        // This object generates individual key-pairs.
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();

        // Boilerplate RSA parameters, no need to change anything
        // except for the RSA key-size (2048). You can use whatever key-size makes sense for you -- 4096, etc.
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 2048, 12));

        // First create the master (signing) key with the generator.
        PGPKeyPair rsakp_sign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
        // Then an encryption subkey.
        PGPKeyPair rsakp_enc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

        // Add a self-signature on the id
        PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();

        // Add signed metadata on the signature.
        // 1) Declare its purpose
        signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        // 2) Set preferences for secondary crypto algorithms to use when sending messages to this key.
        signhashgen.setPreferredSymmetricAlgorithms(false, new int[]{
            SymmetricKeyAlgorithmTags.AES_256,
            SymmetricKeyAlgorithmTags.AES_192,
            SymmetricKeyAlgorithmTags.AES_128
        });
        signhashgen.setPreferredHashAlgorithms(false, new int[]{
            HashAlgorithmTags.SHA256,
            HashAlgorithmTags.SHA1,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA512,
            HashAlgorithmTags.SHA224,});
        // 3) Request senders add additional checksums to the message (useful when verifying unsigned messages.)
        signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        // Create a signature on the encryption subkey.
        PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
        // Add metadata to declare its purpose
        enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        // Objects used to encrypt the secret key.
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);

        // bcpg 1.48 exposes this API that includes s2kcount. Earlier versions use a default of 0x60.
        PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, s2kcount)).build(pass);

        // Finally, create the keyring itself. The constructor takes parameters that allow it to generate the self signature.
        PGPKeyRingGenerator keyRingGen
                = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign,
                        id, sha1Calc, signhashgen.generate(), null,
                        new BcPGPContentSignerBuilder(rsakp_sign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), pske);

        // Add our encryption subkey, together with its signature.
        keyRingGen.addSubKey(rsakp_enc, enchashgen.generate(), null);
        return keyRingGen;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnEnviar;
    private javax.swing.JCheckBox jCheckBoxEncrypt;
    private javax.swing.JCheckBox jCheckBoxSign;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
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

    public void setChatHistory() {
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
                            String result = decryptMessage(history.getMessages().get(i).getText(), "./privada.asc", password.toCharArray());
                            if (result != null) {
                                txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": " + result);
                            } else {
                                txtMsgRecebida.append(history.getMessages().get(i).getUsername() + ": Sended an encrypted message");
                            }
                        } else {
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
                }
            } catch (IOException | SlackApiException ex) {
                Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchProviderException ex) {
                Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private void setRTM() {
        Thread thread = new Thread(new RTMRunnable(slack, token));
        thread.start();
    }

    public String getValueListDm() {
        return listDM.getSelectedValue();
    }
}
