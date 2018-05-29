/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack.gui;

import com.github.seratch.jslack.api.model.Channel;
import com.github.seratch.jslack.api.model.User;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JOptionPane;
import pt.ipb.ssi.chatslack.slack.SlackImpl;

/**
 *
 * @author Douglas Folletto
 */
public class FileUpload extends javax.swing.JFrame {

    /**
     * Creates new form FileUpload
     */
    List<Channel> channels;
    SlackImpl slackImpl;
    String token;
    File file;
    Chat_2 chat;

    private FileUpload() {
        initComponents();
    }

    public FileUpload(SlackImpl slackImpl, String token, File file, Chat_2 chat) {
        initComponents();
        this.token = token;
        this.slackImpl = slackImpl;
        this.file = file;
        this.chat = chat;
        if (file != null) {
            txtTitulo.setText(file.getName());
            //jImagem.set(new FileReader(file.getAbsolutePath()), null);
            channels = slackImpl.getListChannels();
            List<User> users = slackImpl.getListUsers();
            for (Channel channel : channels) {
                cbChannel.addItem(channel.getName());
            }
            for (User user : users) {
                if (!user.isBot()) {
                    cbChannel.addItem(user.getName());
                }
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

        jFileChooser1 = new javax.swing.JFileChooser();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        txtTitulo = new javax.swing.JTextField();
        cbChannel = new javax.swing.JComboBox<>();
        btnEnviar = new javax.swing.JButton();
        btnCancelar = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        jLabel2.setText("Titulo");

        jLabel3.setText("Compartilhar com");

        btnEnviar.setText("Enviar");
        btnEnviar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEnviarActionPerformed(evt);
            }
        });

        btnCancelar.setText("Cancelar");
        btnCancelar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCancelarActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btnCancelar)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnEnviar))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel3)
                            .addComponent(jLabel2))
                        .addGap(39, 39, 39)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(txtTitulo)
                            .addComponent(cbChannel, 0, 191, Short.MAX_VALUE))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(txtTitulo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(cbChannel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnEnviar)
                    .addComponent(btnCancelar))
                .addGap(0, 13, Short.MAX_VALUE))
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void btnEnviarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEnviarActionPerformed
        List<String> listChannel = new ArrayList<>();

        String x = String.valueOf(cbChannel.getSelectedItem());
        boolean isChannel = false;
        for (Channel channel : channels) {
            if (channel.getName().equals(x)) {
                isChannel = true;
            }
        }

        if (!isChannel) {
            //se não for um canal
            // então procurar na lista de usuarios;
            List<User> users = slackImpl.getListUsers();
            for (User user : users) {
                if (user.getName().equals(x)) {
                    //Pegar o id do canal do usuario
                    String channelByUser = slackImpl.getChannelByUser(user.getId());
                    listChannel.add(channelByUser);
                }
            }
        } else {
            listChannel.add(x);
        }
        boolean response = slackImpl.sendFile(file, listChannel, txtTitulo.getText());
        if (response) {
            JOptionPane.showMessageDialog(null, "Arquivo enviado!");
            chat.setChatHistory();
            dispose();
        } else {
            JOptionPane.showMessageDialog(null, "Arquivo não enviado!");
        }
    }//GEN-LAST:event_btnEnviarActionPerformed

    private void btnCancelarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelarActionPerformed
        dispose();
    }//GEN-LAST:event_btnCancelarActionPerformed
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnCancelar;
    private javax.swing.JButton btnEnviar;
    private javax.swing.JComboBox<String> cbChannel;
    private javax.swing.JFileChooser jFileChooser1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JTextField txtTitulo;
    // End of variables declaration//GEN-END:variables
}
