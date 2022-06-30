
package jpcap;

import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.WindowConstants;
import static jpcap.MACMod.macMasterFile;

public class AddMacToMasterFile {
    
//--------------------------------------Add To Master File--------------------------------------
    static JFrame addMacToMasterFileFrame = new JFrame("Add MAC");
    static JTextField addMacToMasterFileTxt = new JTextField();
    static JButton addMacToMasterFileBtn = new JButton("Add");
    static JButton addMacToMasterFileCancel = new JButton("Cancel");
    
    public static void addMacToMaster(){
        try{
            GUI();
        }catch(Exception ex){
            JOptionPane.showMessageDialog(null, ex);
        }
    }
    
    public static void GUI(){
        
        int txtBoxleft=5;
        
        int buttonTop=40;
        int buttonLeft=142;
        int textTop=10;
        int fromBottom=25;
        int buttonRight=55;
        
        int textRight=255;
        
//        ----------------------Main Window-----------------------------
        addMacToMasterFileFrame.setSize(270,100);
        addMacToMasterFileFrame.setLocation(350, 150);
        addMacToMasterFileFrame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        addMacToMasterFileFrame.setResizable(false);
        addMacToMasterFileFrame.getContentPane().setLayout(null);   
        
//      ------------------------Text Area------------------------
        addMacToMasterFileTxt.setForeground(MainProgram.blackColor);
        addMacToMasterFileTxt.setMargin(new Insets(0,0,0,0));
        addMacToMasterFileTxt.requestFocus(true);
        addMacToMasterFileTxt.setHorizontalAlignment(SwingConstants.CENTER);
        addMacToMasterFileFrame.getContentPane().add(addMacToMasterFileTxt);
        addMacToMasterFileTxt.setBounds(txtBoxleft, textTop, textRight, fromBottom);  
        addMacToMasterFileTxt.setVisible(true);
        
        
//      ------------------------Add Button------------------------
        addMacToMasterFileBtn.setForeground(MainProgram.blackColor);
        addMacToMasterFileBtn.setBackground(MainProgram.greenButtonColor);
        addMacToMasterFileBtn.setMargin(new Insets(0,0,0,0));
        addMacToMasterFileBtn.addActionListener((ActionEvent X) -> {
            Action_BTN_ADDMACFunction(X);
        });
        addMacToMasterFileFrame.getContentPane().add(addMacToMasterFileBtn);
        addMacToMasterFileBtn.setBounds(buttonLeft, buttonTop, buttonRight, fromBottom);  
        addMacToMasterFileBtn.setVisible(true);
        
//      ------------------------Cancel Button------------------------
        addMacToMasterFileCancel.setForeground(MainProgram.whiteColor);
        addMacToMasterFileCancel.setBackground(MainProgram.redColorStatus);
        addMacToMasterFileCancel.setMargin(new Insets(0,0,0,0));
        addMacToMasterFileCancel.addActionListener((ActionEvent X) -> {
            try {
                Action_BTN_CANCELFunction(X);
            } catch (IOException ex) {
                Logger.getLogger(AddMacToMasterFile.class.getName()).log(Level.SEVERE, null, ex);
            }
        });

        addMacToMasterFileFrame.getContentPane().add(addMacToMasterFileCancel);
        addMacToMasterFileCancel.setBounds(buttonLeft+60, buttonTop, buttonRight, fromBottom);  
        addMacToMasterFileCancel.setVisible(true);
        
        addMacToMasterFileFrame.setVisible(true);        
    }
    
    public static void Action_BTN_ADDMACFunction(ActionEvent X){
        String addedMac;
        File fin2 = new File(macMasterFile);
        addedMac = addMacToMasterFileTxt.getText();
        addedMac = addedMac.replaceAll("\\s+","");
        if(!"".equals(addedMac))
            try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(macMasterFile, true)))) {
                try{
                    out.println(addedMac);
                }catch(Exception ex){
                    
                }
                JOptionPane.showMessageDialog(null, addedMac+" added to safe state.");
                addMacToMasterFileTxt.setText("");
            }catch (IOException e) {
                JOptionPane.showMessageDialog(null, e);
            }
    }
    
    public static void Action_BTN_CANCELFunction(ActionEvent X) throws IOException{
        addMacToMasterFileFrame.setVisible(false);
        addMacToMasterFileFrame.dispose();
        cleanMasterFile.readMac();
    }
}