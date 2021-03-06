/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack.gui;

import com.github.seratch.jslack.Slack;
import com.github.seratch.jslack.api.methods.SlackApiException;
import com.github.seratch.jslack.api.methods.request.auth.AuthTestRequest;
import com.github.seratch.jslack.api.methods.response.auth.AuthTestResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;

/**
 *
 * @author Douglas Folletto
 */
public class Login extends javax.swing.JFrame {

    /**
     * Creates new form Login
     */
    public Login() {
        initComponents();
        //txtToken.setText("xoxp-353804391270-352655713073-354162492966-bcbf0e04ed28e154e7e939d14ddd3f42");
        //txtBotUserToken.setText("xoxb-353405684213-gVzzTC72SzkGPzoPfjIO7RHE");
        txtToken.setText("xoxp-353804391270-353047442645-366797798246-29cbe85f7926dd7727dea1ca5148662e");
        txtBotUserToken.setText("xoxb-353804391270-365361411697-hRufgIFBtPBU1rEoBIgL5iaR");
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        txtBotUserToken = new javax.swing.JTextField();
        btnLogin = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        txtToken = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Login ");

        jLabel1.setText("Bot User OAuth Access Token ");

        btnLogin.setText("Login");
        btnLogin.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnLoginActionPerformed(evt);
            }
        });

        jLabel2.setText("OAuth Access Token ");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(txtToken)
                    .addComponent(txtBotUserToken))
                .addContainerGap())
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(361, Short.MAX_VALUE)
                .addComponent(btnLogin)
                .addGap(332, 332, 332))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(21, 21, 21)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(txtToken, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(txtBotUserToken, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(btnLogin)
                .addGap(26, 26, 26))
        );

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void btnLoginActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnLoginActionPerformed
        if (txtBotUserToken.getText().trim().isEmpty()) {
            JOptionPane.showMessageDialog(null, "Informe o Token!");
        } else if (txtBotUserToken.getText().contains("xoxb")) {
            try {
                // Faça a conexão para o slack com o token informado
                // Cria uma instancia do Slack
                Slack slack = Slack.getInstance();
                // Pega o token informado
                String botUserToken = txtBotUserToken.getText().trim();
                String token = txtToken.getText().trim();

                // Realiza uma consulta para validar o token
                AuthTestResponse responseBotUserToken = slack.methods().authTest(AuthTestRequest.builder().token(botUserToken).build());
                AuthTestResponse responseToken = slack.methods().authTest(AuthTestRequest.builder().token(token).build());
                if (!responseToken.isOk()) {
                    JOptionPane.showMessageDialog(null, "Erro ao acessar o Slack com o OAuth Access Token");
                }
                if (responseBotUserToken.isOk()) {
                    // Caso teve sucesso na validação com o token
                    // Abre a janela do chat
                    //Chat janela = new Chat(botUserToken, token);
                    Chat_2 janela = new Chat_2(botUserToken, token);

                    janela.setVisible(true);
                    this.setVisible(false);
                  /*  new Chat(botUserToken, token).setVisible(true);
                    setVisible(false);*/

                } else {
                    JOptionPane.showMessageDialog(null, "Erro ao acessar o Slack com o Bot User OAuth Access Token");
                }
            } catch (IOException | SlackApiException ex) {
                Logger.getLogger(Login.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            JOptionPane.showMessageDialog(null, "Token Inválido");
        }
    }//GEN-LAST:event_btnLoginActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnLogin;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JTextField txtBotUserToken;
    private javax.swing.JTextField txtToken;
    // End of variables declaration//GEN-END:variables
}
