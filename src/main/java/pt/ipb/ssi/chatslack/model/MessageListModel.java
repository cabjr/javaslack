/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack.model;

import com.github.seratch.jslack.api.model.Message;

/**
 *
 * @author Douglas Folletto
 */
public class MessageListModel {

    private String userName;
    private String message;
    String[] partsMessage;
    private Message messageSlack;

    public MessageListModel(String userName, String message, Message messageSlack) {
        this.userName = userName;
        this.message = message;
        this.partsMessage = message.split("\n");
        this.messageSlack = messageSlack;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
        this.partsMessage = message.split("\n");
    }

    public String[] getPartsMessage() {
        return partsMessage;
    }

    public void setPartsMessage(String[] partsMessage) {
        this.partsMessage = partsMessage;
    }

    public Message getMessageSlack() {
        return messageSlack;
    }

    public void setMessageSlack(Message messageSlack) {
        this.messageSlack = messageSlack;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (messageSlack.getFile() == null) {
            for (int i = 0; i < partsMessage.length; i++) {
                if (i == 0) {
                    sb.append(userName).append(" : ").append(System.getProperty("line.separator")).append(partsMessage[i]);
                } else {
                    sb.append(System.getProperty("line.separator")).append(partsMessage[i]);
                }

            }
        } else {
            //Mudando um pouco sobre a forma que exibe a mensagem de download
            
            sb.append(userName).append(" : ").append(System.getProperty("line.separator"));
            sb.append("uploaded a file:  ").append(messageSlack.getFile().getName()).append(System.getProperty("line.separator"));;
            sb.append("click the right button to download the file");

        }
        return sb.toString();
    }

}
