/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ipb.ssi.chatslack.model;

/**
 *
 * @author Douglas Folletto
 */
public class MessageListModel {

    private String userName;
    private String message;
    String[] partsMessage;

    public MessageListModel(String userName, String message) {
        this.userName = userName;
        this.message = message;
        this.partsMessage = message.split("\n");
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < partsMessage.length; i++) {
            if (i == 0) {
                sb.append(userName).append(" : ").append(System.getProperty("line.separator")).append(partsMessage[i]);
            } else {
                sb.append(System.getProperty("line.separator")).append(partsMessage[i]);
            }

        }
        return sb.toString();
    }

}
