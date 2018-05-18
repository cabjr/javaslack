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
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
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
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
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
        jCheckBoxEncrypt = new javax.swing.JCheckBox();
        jCheckBoxSign = new javax.swing.JCheckBox();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenuItem5 = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenuItem2 = new javax.swing.JMenuItem();
        jMenuItem3 = new javax.swing.JMenuItem();
        jMenuItem4 = new javax.swing.JMenuItem();
        jMenuItem6 = new javax.swing.JMenuItem();

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

        jCheckBoxEncrypt.setText("Encrypt");

        jCheckBoxSign.setText("Sign");

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

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jCheckBoxSign)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jCheckBoxEncrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 70, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
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
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 449, javax.swing.GroupLayout.PREFERRED_SIZE))))
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
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jCheckBoxEncrypt)
                    .addComponent(jCheckBoxSign))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void btnEnviarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEnviarActionPerformed
        // Clique no botão de enviar
        if (listCanais.getSelectedIndex() != -1) {
            String channelID = canais.get(CanalAtual).getId();
            System.out.println("Channel ID: " + channelID);
            if (!txtMsgEnviar.getText().isEmpty()) {
                String mensagem = txtMsgEnviar.getText();
                try {
                    System.out.println(slack.methods().chatPostMessage(ChatPostMessageRequest.builder().asUser(false).text(mensagem).username("Bot com nick que eu quiser").token(token).channel(channelID).build()));
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

    private void jMenuItem5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem5ActionPerformed
        System.exit(0);
    }//GEN-LAST:event_jMenuItem5ActionPerformed

    private void jMenuItem3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem3ActionPerformed
        ArmoredOutputStream pubout = null;
        try {
            char pass[] = {'h', 'e', 'l', 'l', 'o'};
            PGPKeyRingGenerator krgen = generateKeyRingGenerator("alice@example.com", pass);
            // Generate public key ring, dump to file.
            PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();
            pubout = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream("./dummy.asc")));
            pkr.encode(pubout);
            pubout.close();
            // Generate private key, dump to file.
            // PGPSecretKeyRing privateKey = krgen.generateSecretKeyRing();

            PGPSecretKeyRing skr = krgen.generateSecretKeyRing();
            BufferedOutputStream secout = new BufferedOutputStream(new FileOutputStream("./dummy.skr"));
            skr.encode(secout);
            secout.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                pubout.close();
            } catch (IOException ex) {
                Logger.getLogger(Chat.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_jMenuItem3ActionPerformed

    private void jMenuItem6ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem6ActionPerformed

    }//GEN-LAST:event_jMenuItem6ActionPerformed

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
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JMenuItem jMenuItem3;
    private javax.swing.JMenuItem jMenuItem4;
    private javax.swing.JMenuItem jMenuItem5;
    private javax.swing.JMenuItem jMenuItem6;
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
