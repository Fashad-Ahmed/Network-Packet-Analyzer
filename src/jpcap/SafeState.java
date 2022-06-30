/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jpcap;

import java.awt.Color;
import java.awt.Font;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.WindowConstants;

public class SafeState {
    
    static boolean foundMac = false;
    
    static JFrame readMaster = new JFrame("Safe State MAC");
    static JScrollPane scrollareaView = new JScrollPane();
    static JButton removeBtn= new JButton("Remove");
    static JTextField removeTxtBx = new JTextField();
    static List<String> macTemp = new ArrayList<>();
    static String macMasterFile="D:\\IDS\\MacFolder\\MasterFile.txt";
    static int z;
    
    public static void readMasterFile(ActionEvent X){
        try{
            z=0;
            String macReadMaster;
            try (BufferedReader readMacFromMasterFile = new BufferedReader(new FileReader(macMasterFile))) {
                //           ----------------------Main Window-----------------------------
                readMaster.setSize(MACMod.mainFrameWidth,MACMod.mainFrameHeight);
                readMaster.setLocation(350, 150);
                readMaster.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
                readMaster.setResizable(false);
                readMaster.getContentPane().setLayout(null);
                
                //        ----------------------Scroll Panel-----------------------------
                scrollareaView.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                scrollareaView.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
                scrollareaView.setViewportView(MACMod.intrudersList);
                scrollareaView.setBounds(1, 1, MACMod.scrollPaneWidth, MACMod.mainFrameHeight-60);
                readMaster.getContentPane().add(scrollareaView);
                
                //        ----------------------Intruder List-----------------------------
                MACMod.intrudersList.setEditable(false);
                MACMod.intrudersList.setBackground(Color.LIGHT_GRAY);
                MACMod.intrudersList.setForeground(new Color(0, 120, 0));
                MACMod.intrudersList.setFont(new Font("Times New Roman",1,20));
                MACMod.intrudersList.setLineWrap(false);
                
                MACMod.intrudersList.setText("");
                
                int iTemp=0;
                
                while((macReadMaster=readMacFromMasterFile.readLine())!=null){
                    z++;
                    iTemp++;
                    MACMod.intrudersList.append(iTemp+".  "+macReadMaster+"\n");
                    macTemp.add(macReadMaster);
                }
                //      --------------------------------Selection------------------------------------
                readMaster.getContentPane().add(removeTxtBx);
                removeTxtBx.setVisible(true);
                removeTxtBx.requestFocus();
                removeTxtBx.setBorder(MACMod.border);
                removeTxtBx.setHorizontalAlignment(SwingConstants.CENTER);
                removeTxtBx.setMargin(new Insets(0,0,0,0));
                removeTxtBx.setBounds(MACMod.addMacTextBoxLeft, MACMod.btnFromTop+25, MACMod.textBoxFromRight+150, MACMod.btnFromBottom);
                removeTxtBx.requestFocus(true);
                
                //        ----------------------Remove Button-----------------------------
                removeBtn.setBackground(MainProgram.redColorStatus);
                removeBtn.setForeground(MainProgram.whiteColor);
                removeBtn.setMargin(new Insets(0,0,0,0));
                removeBtn.addActionListener((ActionEvent Rem) -> {
                    try {
                        removeMacFromMasterFile(Rem);
                    } catch (IOException ex) {
                        Logger.getLogger(SafeState.class.getName()).log(Level.SEVERE, null, ex);
                    }
                });
                readMaster.getContentPane().add(removeBtn);
                removeBtn.setBounds(MACMod.addBtnLeft+202-25,MACMod.btnFromTop+25,MACMod.btnFromRight+5,MACMod.btnFromBottom+2);
                removeBtn.setVisible(true);
                
                readMaster.setVisible(true);
            }
        }catch(Exception e){
            
        }
    }
    
    public static void removeMacFromMasterFile(ActionEvent X) throws IOException{
        try{
            String removeMacText;
            List<String> masterList = new ArrayList<>();

            removeMacText=(removeTxtBx.getText()).replaceAll("\\s+","");

            File master = new File(macMasterFile);
            String tempMac;
            BufferedReader br = new BufferedReader(new FileReader(macMasterFile));
            while((tempMac=br.readLine())!=null){
                masterList.add(tempMac);
            }
            br.close();
            master.delete();

            try(PrintWriter write = new  PrintWriter(new BufferedWriter(new FileWriter(MACMod.macMasterFile)))) {
                masterList.remove(removeMacText);
                
                masterList.stream().forEach((value) -> {
                    write.println(value);
                });
                write.close();
            }
            }catch(Exception e){
                System.out.println(e);
        }
        removeTxtBx.setText("");
        readMasterFile(X);
    }
}