
package jpcap;

import java.awt.Color;
import java.awt.Font;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.WindowConstants;
import static jpcap.MACMod.macMasterFile;

/**
 *
 * @Fashad-Ahmed 
 */

public final class MainProgram {
    
    boolean textBoxVisibilityCount = false;
    public static boolean scanButtonPressed = false;
    
    public static String COPYRIGHT  = "\u00a9";
    
    NetworkInterface[] NETWORK_INTERFACES;
    JpcapCaptor CAP;
    
    static int interfaceCount=0;
    
    int COUNTER =0;
    int INDEX=0 ;
    
    int btnFromTop=435;
    int btnFromBottom=22;
    int btnFromRight=70;
    int btnWidth=70;
    
    int loadBtnLeft=5;
    int listBtnLeft=btnWidth+loadBtnLeft;
    int selectionTextBoxLeft=btnWidth+listBtnLeft;
    int selectBtnLeft=btnWidth+selectionTextBoxLeft;
    int captureBtnLeft=btnWidth+selectBtnLeft;
    int stopBtnLeft=btnWidth+captureBtnLeft;
    int saveBtnLeft=btnWidth+stopBtnLeft; 
    int scanBtnLeft=btnWidth+saveBtnLeft;
    int addBtnLeft=btnWidth+scanBtnLeft;
    int viewBtnLeft=btnWidth+addBtnLeft;
    
    int exitBtnLeft=720;
    
    boolean CaptureState = false;
    jpcap_thread CAPTAIN;
    
    static Color blackColor = new Color(0,0,0);
    static Color blueColor = new Color(133, 38, 255);
    static Color whiteColor =  new Color(255, 255, 255);
    static Color greenButtonColor =  new Color(38, 255, 154);
    static Color greenColorStatus =  new Color(0, 255, 157);
    static Color redColorStatus =  new Color(193, 54, 0);
    static Color disabledColor = new Color(210, 210, 210);
        
    JFrame MainWindow = new JFrame("Network Capturer"+COPYRIGHT);
    public static JTextArea outputText = new JTextArea();
    JScrollPane scrollarea = new JScrollPane();
    
    JButton BTN_CAPTURE = new JButton("CAPTURE");
    JButton BTN_STOP = new JButton("STOP");
    JButton BTN_SELECT = new JButton("SELECT");
    JButton BTN_SAVE = new JButton("SAVE");
    JButton BTN_LOAD = new JButton("LOAD");
    JButton BTN_EXIT = new JButton("EXIT");
    JButton BTN_LIST = new JButton("LIST");
    JButton BTN_SCAN = new JButton("SCAN");
    JButton BTN_VIEW_MASTER = new JButton("SAVED");
    
    JButton BTN_ADD_MAC = new JButton("ADD Mac");
    
    JTable tableBtnsAndAll = new JTable();
    
    ButtonGroup BG_Filter_Enable_Disable = new ButtonGroup();
    ButtonGroup BG_ports = new ButtonGroup();

    JLabel Filters_Selection = new JLabel("Select Filters");
    JTextField TF_SelectInterface = new JTextField();
    
//--------------------------------------Filters--------------------------------------    
    int filtersLeft=215;
    int filtersTop=405;
    int filtersRight=94;
    int filtersBottom=25;
    
    int radioBtnWdthDiff=75;
    
    int filterFirstRow=390;
    int filterSecondRow = 410;
    int sectionGap=110;
    int filterEnableleft=5;
    int filterDisableLeft=filterEnableleft+60;
    int filterENADISTop=filtersTop;
    int filterENADISRight=filtersRight-28;
    int filterENADISBottom=filtersBottom;
    
    int IMAPleft=filtersLeft;
    int IMAPTop=filterFirstRow;
    int IMAPRight=filtersRight-17;
    int IMAPBottom=filtersBottom;
    
    int IMAPSleft=IMAPleft;
    int IMAPSTop=filterSecondRow;
    int IMAPSRight=filtersRight-17;
    int IMAPSBottom=filtersBottom;
    
    int SMTPLeft=IMAPleft+radioBtnWdthDiff;
    int SMTPTop=IMAPTop;
    int SMTPRight=filtersRight-18;
    int SMTPBottom=filtersBottom;
    
    int POPLeft=IMAPSleft+radioBtnWdthDiff;
    int POPTop=IMAPSTop;
    int POPRight=filtersRight-18;
    int POPBottom=filtersBottom;
    
    int HTTPLeft=sectionGap+SMTPLeft;
    int HTTPTop=filterFirstRow;
    int HTTPRight=filtersRight;
    int HTTPBottom=filtersBottom;
    
    int HTTPSLeft=HTTPLeft;
    int HTTPSTop=filterSecondRow;
    int HTTPSRight=filtersRight;
    int HTTPSBottom=filtersBottom;
    
    int FTPLeft=sectionGap+HTTPLeft;
    int FTPTop=filterFirstRow;
    int FTPRight=filtersRight;
    int FTPBottom=filtersBottom;
    
    int SAMBALeft=FTPLeft;
    int SAMBATop=filterSecondRow;
    int SAMBARight=filtersRight;
    int SAMBABottom=filtersBottom;
    
    int TELNETLeft=sectionGap+FTPLeft;
    int TELNETTop=filterFirstRow;
    int TELNETRight=filtersRight-20;
    int TELNETBottom=filtersBottom;
    
    int SSHLeft=TELNETLeft;
    int SSHTop=filterSecondRow;
    int SSHRight=filtersRight-20;
    int SSHBottom=filtersBottom;
    
    int SQLLeft=sectionGap+SSHLeft-25;
    int SQLTop=filterFirstRow;
    int SQLRight=filtersRight;
    int SQLBottom=filtersBottom;
    
    int DNSLeft=SQLLeft;
    int DNSTop=filterSecondRow;
    int DNSRight=filtersRight;
    int DNSBottom=filtersBottom;
    
    String filterFontName = "Times New Roman";
    int filterFontSize=10;
    
    JRadioButton RB_filter_enable = new JRadioButton("Enable");
    JRadioButton RB_filter_disable = new JRadioButton("Disable");
    JRadioButton RB_port_HTTP = new JRadioButton("HTTP(80)");
    JRadioButton RB_port_SSL = new JRadioButton("HTTP SSL(443)");
    JRadioButton RB_port_FTP = new JRadioButton("FTP(21)");
    JRadioButton RB_port_SSH = new JRadioButton("SSH");
    JRadioButton RB_port_Telnet = new JRadioButton("Telnet");
    JRadioButton RB_port_SMTP = new JRadioButton("SMTP(25)");
    JRadioButton RB_port_POP3 = new JRadioButton("POP3(110)");
    JRadioButton RB_port_IMAP = new JRadioButton("IMAP(143)");
    JRadioButton RB_port_IMAPS = new JRadioButton("IMAPS(993)");
    JRadioButton RB_port_DNS = new JRadioButton("DNS(53)");
    JRadioButton RB_port_SAMBA = new JRadioButton("SAMBA(137)");
    JRadioButton RB_port_SQL = new JRadioButton("SQL(118)");
    
    
    JLabel L_Title = new JLabel("packet capturer");
    JLabel L_FilterStatus = new JLabel("Port Filter Status");
    JLabel L_FilterPresets = new JLabel("Port Filter Presets");
    JLabel L_SpecialPort = new JLabel("Special Port #");
    public static JTextField TF_getcommand = new JTextField();
    JTextField TF_SpecialPort = new JTextField();
    JLabel L_FilterStatusBox = new JLabel("ALL PORTS DISABLED");
    JLabel filterEnDi = new JLabel("Filters");
    
    String fileLocation = "D://CapturedData.txt";
    
    public static void main(String args[]) throws IOException{
        MainProgram new_interface = new MainProgram();
    }
    
    public MainProgram() throws IOException{
        MACMod.makeDirectory();
        try{
            File masterFile=new File(macMasterFile);
            if(!masterFile.exists()) masterFile.createNewFile();
        }catch(Exception ex){
        }
        BuildGUI();        
        DisableButtons();
    }
    
    public void BuildGUI() throws IOException{
        
//        ----------------------Main Window-----------------------------
        MainWindow.setSize(800,500);
        MainWindow.setLocation(350, 150);
        MainWindow.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        MainWindow.setResizable(false);
        MainWindow.getContentPane().setLayout(null);
        
//        ----------------------Scroll Panel-----------------------------        
        scrollarea.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollarea.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollarea.setViewportView(outputText);        
        scrollarea.setBackground(blueColor);
        scrollarea.setAutoscrolls(true);
        scrollarea.setVisible(true);
        scrollarea.setBounds(1, 1, 793, 375);
        MainWindow.getContentPane().add(scrollarea); 
        
//        ----------------------Output Screen----------------------------
        outputText.setEditable(false);
        outputText.setVisible(true);
        outputText.setAutoscrolls(true);
        outputText.setBackground(disabledColor);
        outputText.setFont(new Font("Calibri",0,13));
        outputText.setForeground(blackColor);
        outputText.setLineWrap(true);

//  -------------------------List Button-------------------------------
        BTN_LIST.setBackground(greenButtonColor);
        BTN_LIST.setForeground(blackColor);
        BTN_LIST.addActionListener((ActionEvent X) -> {
            Action_BTN_LIST(X);
        });
        MainWindow.getContentPane().add(BTN_LIST);
        BTN_LIST.setBounds(listBtnLeft,btnFromTop,btnFromRight,btnFromBottom);
        
//        ----------------------Select Button-----------------------------        
        BTN_SELECT.setBackground(disabledColor);
        BTN_SELECT.setForeground(blackColor);
        BTN_SELECT.setMargin(new Insets(0,0,0,0));
        BTN_SELECT.addActionListener((ActionEvent X) -> {
            Action_BTN_SELECT(X);
        });
        MainWindow.getContentPane().add(BTN_SELECT);
        BTN_SELECT.setBounds(selectBtnLeft,btnFromTop,btnFromRight,btnFromBottom);
        
//        ----------------------Capture Button-----------------------------                
        BTN_CAPTURE.setBackground(disabledColor);
        BTN_CAPTURE.setForeground(blackColor);
        BTN_CAPTURE.setMargin(new Insets(0,0,0,0));
        BTN_CAPTURE.addActionListener(this::Action_BTN_CAPTURE);
        MainWindow.getContentPane().add(BTN_CAPTURE);
        BTN_CAPTURE.setBounds(captureBtnLeft,btnFromTop,btnFromRight,btnFromBottom);
        
//        ----------------------Stop Button-----------------------------        
        BTN_STOP.setBackground(disabledColor);
        BTN_STOP.setForeground(blackColor);
        BTN_STOP.setMargin(new Insets(0,0,0,0));
        BTN_STOP.addActionListener(this::Action_BTN_STOP);
        MainWindow.getContentPane().add(BTN_STOP);
        BTN_STOP.setBounds(stopBtnLeft,btnFromTop,btnFromRight,btnFromBottom);

//        ----------------------Save Button-----------------------------        
        BTN_SAVE.setBackground(disabledColor);
        BTN_SAVE.setForeground(blackColor);
        BTN_SAVE.setMargin(new Insets(0,0,0,0));
        BTN_SAVE.addActionListener((ActionEvent X) -> {
            try {
                Action_BTN_SAVE(X);
            } catch (FileNotFoundException ex) {
                Logger.getLogger(MainProgram.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(MainProgram.class.getName()).log(Level.SEVERE, null, ex);
            }
        });
        MainWindow.getContentPane().add(BTN_SAVE);
        BTN_SAVE.setBounds(saveBtnLeft,btnFromTop,btnFromRight,btnFromBottom);
       
//        ----------------------Load Button-----------------------------      
        BTN_LOAD.setBackground(greenButtonColor);
        BTN_LOAD.setForeground(blackColor);
        BTN_LOAD.setText("LOAD");
        BTN_LOAD.setToolTipText("Load captured file.");
        BTN_LOAD.setMargin(new Insets(0,0,0,0));
        BTN_LOAD.addActionListener((ActionEvent X) -> {
            try {
                Action_BTN_LOAD(X);
            } catch (FileNotFoundException ex) {
                Logger.getLogger(MainProgram.class.getName()).log(Level.SEVERE, null, ex);
            }
        });
        MainWindow.getContentPane().add(BTN_LOAD);
        BTN_LOAD.setBounds(loadBtnLeft,btnFromTop,btnFromRight,btnFromBottom);

//        ----------------------Interface Selection-----------------------------      
        TF_SelectInterface.setForeground(blackColor);
        TF_SelectInterface.setVisible(false);
        MainWindow.getContentPane().add(TF_SelectInterface);
        TF_SelectInterface.setHorizontalAlignment(SwingConstants.CENTER);
        TF_SelectInterface.setMargin(new Insets(0,0,0,0));
        TF_SelectInterface.setBounds(selectionTextBoxLeft, btnFromTop, btnFromRight, btnFromBottom);
        
        
//        ----------------------Scan Button-----------------------------      
        BTN_SCAN.setBackground(greenButtonColor);
        BTN_SCAN.setForeground(blackColor);
        BTN_SCAN.setText("SCAN");
        BTN_SCAN.setMargin(new Insets(0,0,0,0));
        BTN_SCAN.addActionListener((ActionEvent X) -> {
            try {
                Action_BTN_SCAN(X);
            } catch (FileNotFoundException ex) {
                Logger.getLogger(MainProgram.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(MainProgram.class.getName()).log(Level.SEVERE, null, ex);
            }
        });
        MainWindow.getContentPane().add(BTN_SCAN);
        BTN_SCAN.setBounds(scanBtnLeft,btnFromTop,btnFromRight,btnFromBottom);        

//        ----------------------Add Button-----------------------------      
        BTN_ADD_MAC.setBackground(greenButtonColor);
        BTN_ADD_MAC.setForeground(blackColor);
        BTN_ADD_MAC.setText("ADD");
        BTN_ADD_MAC.setMargin(new Insets(0,0,0,0));
        BTN_ADD_MAC.addActionListener((ActionEvent X) -> {
            Action_BTN_ADD_MAC(X);
        });
        MainWindow.getContentPane().add(BTN_ADD_MAC);
        BTN_ADD_MAC.setBounds(addBtnLeft,btnFromTop,btnFromRight,btnFromBottom);                
        
//        ----------------------Exit Button-----------------------------        
        BTN_EXIT.setBackground(redColorStatus);
        BTN_EXIT.setForeground(whiteColor);
        BTN_EXIT.setMargin(new Insets(0,0,0,0));
        BTN_EXIT.addActionListener((ActionEvent X) -> {
            try {
                Action_BTN_EXIT(X);
            } catch (IOException ex) {
                Logger.getLogger(MainProgram.class.getName()).log(Level.SEVERE, null, ex);
            }
        });
        MainWindow.getContentPane().add(BTN_EXIT);
        BTN_EXIT.setBounds(exitBtnLeft,btnFromTop,btnFromRight,btnFromBottom);
       
//        ----------------------View Button-----------------------------     
        BTN_VIEW_MASTER.setBackground(greenButtonColor);
        BTN_VIEW_MASTER.setForeground(blackColor);
        BTN_VIEW_MASTER.setText("VIEW");
        BTN_VIEW_MASTER.setMargin(new Insets(0,0,0,0));
        BTN_VIEW_MASTER.addActionListener((ActionEvent X) -> {
            SafeState.readMasterFile(X);
        });
        MainWindow.getContentPane().add(BTN_VIEW_MASTER);
        BTN_VIEW_MASTER.setBounds(viewBtnLeft,btnFromTop,btnFromRight,btnFromBottom);        
        
//      --------------------------------Filters Selection------------------------------------
        MainWindow.getContentPane().add(filterEnDi);
        filterEnDi.setBounds(filtersLeft-160,filterFirstRow-2,filtersRight,filtersBottom);
        
        MainWindow.getContentPane().add(Filters_Selection);
        Filters_Selection.setBounds(filtersLeft-74,filterFirstRow+10,filtersRight,filtersBottom);
        
        BG_Filter_Enable_Disable.add(RB_filter_enable);
        RB_filter_enable.addActionListener((ActionEvent X) -> {
            Action_B_ENABLE(X);
        });
        MainWindow.getContentPane().add(RB_filter_enable);
        RB_filter_enable.setBounds(filterEnableleft,filterENADISTop+2,filterENADISRight-2,filterENADISBottom-2);
        
        
        BG_Filter_Enable_Disable.add(RB_filter_disable);
        RB_filter_disable.addActionListener((ActionEvent X) -> {
            Action_B_DISABLE(X);
        });
        MainWindow.getContentPane().add(RB_filter_disable);
        RB_filter_disable.setBounds(filterDisableLeft,filterENADISTop+2,filterENADISRight+5,filterENADISBottom-2);
        
        BG_ports.add(RB_port_IMAP);
        RB_port_IMAP.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_IMAP);
        RB_port_IMAP.setBounds(IMAPleft,IMAPTop, IMAPRight, IMAPBottom);
        
        BG_ports.add(RB_port_IMAPS);
        RB_port_IMAPS.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_IMAPS);
        RB_port_IMAPS.setBounds(IMAPSleft,IMAPSTop, IMAPSRight, IMAPSBottom);
        
        BG_ports.add(RB_port_SMTP);
        RB_port_SMTP.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_SMTP);
        RB_port_SMTP.setBounds(SMTPLeft,SMTPTop, SMTPRight, SMTPBottom);
        
        BG_ports.add(RB_port_POP3);
        RB_port_POP3.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_POP3);
        RB_port_POP3.setBounds(POPLeft , POPTop, POPRight, POPBottom);
        
//------------------*******------------------------        
        BG_ports.add(RB_port_HTTP);
        RB_port_HTTP.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_HTTP);
        RB_port_HTTP.setBounds(HTTPLeft, HTTPTop, HTTPRight, HTTPBottom);
        
        BG_ports.add(RB_port_SSL);
        RB_port_SSL.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_SSL);
        RB_port_SSL.setBounds(HTTPSLeft, HTTPSTop, HTTPSRight, HTTPSBottom);
        
//----------------------***********-----------------------  
        BG_ports.add(RB_port_FTP);
        RB_port_FTP.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_FTP);
        RB_port_FTP.setBounds(FTPLeft, FTPTop, FTPRight,FTPBottom);      
        
        BG_ports.add(RB_port_SAMBA);
        RB_port_SAMBA.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_SAMBA);
        RB_port_SAMBA.setBounds(SAMBALeft, SAMBATop, SAMBARight, SAMBABottom);

//-----------------------***************------------------------        
        BG_ports.add(RB_port_SSH);
        RB_port_SSH.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_SSH);
        RB_port_SSH.setBounds(SSHLeft, SSHTop, SSHRight,SSHBottom);
        
        BG_ports.add(RB_port_Telnet);
        RB_port_Telnet.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_Telnet);
        RB_port_Telnet.setBounds(TELNETLeft, TELNETTop, TELNETRight,TELNETBottom);

//------------------*****************--------------------------------        
        BG_ports.add(RB_port_DNS);
        RB_port_DNS.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_DNS);
        RB_port_DNS.setBounds(DNSLeft, DNSTop, DNSRight, DNSBottom);
        
//-----------------------*************----------------------------------        
        BG_ports.add(RB_port_SQL);
        RB_port_SQL.setFont(new Font(filterFontName,0,filterFontSize));
        MainWindow.getContentPane().add(RB_port_SQL);
        RB_port_SQL.setBounds(SQLLeft, SQLTop, SQLRight, SQLBottom);
        
        filtersDisable();
        
        MainWindow.setVisible(true);   
    }
    
//      --------------------------------Button Functions-----------------------------------
    public void Action_BTN_LIST(ActionEvent X){
        textBoxVisibilityCount=true;
        selectionTextBoxLeft=btnWidth+listBtnLeft;
        BTN_SELECT.setEnabled(true);
        BTN_SELECT.setBackground(greenButtonColor);
        TF_SelectInterface.setEnabled(true);
        TF_SelectInterface.setBounds(selectionTextBoxLeft, btnFromTop, btnFromRight, btnFromBottom);
        TF_SelectInterface.setVisible(true);
        TF_SelectInterface.requestFocus();
        ListNetworkInterfaces();
    }
    
    public void Action_BTN_STOP(ActionEvent X){
        BTN_SELECT.setEnabled(true);
        BTN_SELECT.setBackground(greenButtonColor);
        BTN_LOAD.setEnabled(true);
        BTN_LOAD.setBackground(greenButtonColor);
        BTN_STOP.setEnabled(false);
        BTN_STOP.setBackground(disabledColor);
        BTN_CAPTURE.setEnabled(true);
        BTN_CAPTURE.setBackground(greenButtonColor);
        BTN_SAVE.setEnabled(true);
        BTN_SAVE.setBackground(greenButtonColor);
        BTN_LIST.setEnabled(true);
        BTN_LIST.setBackground(greenButtonColor);
        CaptureState = false;
        CAPTAIN.finished();
    }   

    public void Action_BTN_SELECT(ActionEvent X){
        if(!"".equals(TF_SelectInterface.getText())){
            try{
                int TEMP = Integer.parseInt(TF_SelectInterface.getText());
                if(TEMP<=interfaceCount){
                    ChooseInterface(TEMP);
                    filtersEnable();
                }else{
                    JOptionPane.showMessageDialog(null, "Enter valid interface number only.");
                }
            }catch(NumberFormatException | HeadlessException ex){
                JOptionPane.showMessageDialog(null, "Enter valid interface number only.");
            }
        }
    }
    
    public void Action_BTN_CAPTURE(ActionEvent X){
        filtersDisable();
        BTN_LOAD.setEnabled(false);
        BTN_LOAD.setBackground(disabledColor);
        BTN_SELECT.setEnabled(false);
        BTN_LIST.setBackground(disabledColor);
        BTN_LIST.setEnabled(false);
        BTN_SELECT.setBackground(disabledColor);
        BTN_STOP.setEnabled(true);
        BTN_STOP.setBackground(greenButtonColor);
        BTN_CAPTURE.setEnabled(false);
        BTN_CAPTURE.setBackground(disabledColor);
        outputText.setText("");
        CaptureState=true;
        CapturePackets();
    }
    
    public void Action_BTN_SAVE(ActionEvent X) throws FileNotFoundException, IOException{
        SaveCaptureData();
    }
    
    public void Action_BTN_ADD_MAC(ActionEvent X){
        AddMacToMasterFile.addMacToMaster();
    }
      
    public void Action_BTN_LOAD(ActionEvent X) throws FileNotFoundException{
        LoadCaptureData();
    }
       
    public void Action_BTN_EXIT(ActionEvent X) throws IOException{
        cleanMasterFile.readMac();
        MainWindow.setVisible(false);
        MainWindow.dispose();
    }
    
    public void Action_BTN_SCAN(ActionEvent X) throws IOException{
        BTN_SCAN.setText("SCANNING...");
        MACMod.start();
        BTN_SCAN.setText("SCAN");
    }
        
    public void Action_B_ENABLE(ActionEvent X){
        L_FilterStatusBox.setText("Enabled");
    }
    
    public void Action_B_DISABLE(ActionEvent X){
        L_FilterStatusBox.setText("Disabled");
    }
          
    public void DisableButtons(){
        BTN_CAPTURE.setEnabled(false);
        BTN_STOP.setEnabled(false);
        BTN_SELECT.setEnabled(false);
        BTN_SAVE.setEnabled(false);
    }
    
    public void EnableButtons(){
       BTN_CAPTURE.setEnabled(true);
       BTN_SELECT.setEnabled(true);
       BTN_SAVE.setEnabled(true);
    }
           
    public void ListNetworkInterfaces(){
        int i;
        NETWORK_INTERFACES = JpcapCaptor.getDeviceList();
        outputText.setText("");
        for(i=0;i<NETWORK_INTERFACES.length;i++){
            outputText.append("\n\n--------------------------------------Information From Interface "+i+"--------------------------------------");
            outputText.append("\nInterface Number : "+i);
            outputText.append("\nDescription:"+
            NETWORK_INTERFACES[i].name + "/"+
            NETWORK_INTERFACES[i].description+"}");
            outputText.append("\nDatlink Name : "+
            NETWORK_INTERFACES[i].datalink_name + "/"+
            NETWORK_INTERFACES[i].datalink_description+"}");
            outputText.append("\nMAC address : ");
        }
        interfaceCount=i;
    }
    
    public void CapturePackets(){
        outputText.setText("");
        CAPTAIN = new jpcap_thread(){
        @Override
            public Object construct(){
                outputText.setText("...Capturing packets from interface "+INDEX+"...\n");
                try{
                    CAP = JpcapCaptor.openDevice(JpcapCaptor.getDeviceList()[0],1000,false,20);
                    while(CaptureState){
                        CAP.processPacket(1, new jpcap_capture());
                    }
                    CAP.close();
                }
                catch(Exception X){
                    System.out.print(X);
                }
                return 0;
            }
        @Override
        public void finished(){this.interrupt();}
        };
        CAPTAIN.start();
    }
           
    public void SaveCaptureData() throws FileNotFoundException, IOException{
        String CaptureData = outputText.getText();
        try{
            File DATA = new File(fileLocation);
            try (FileOutputStream DATASTREAM = new FileOutputStream(DATA); PrintStream OUT = new  PrintStream(DATASTREAM)){
                OUT.println(CaptureData);
            }
            JOptionPane.showMessageDialog(null, "Data saved successfully");
        }
        catch(HeadlessException X){
            JOptionPane.showMessageDialog(null,"File access ERROR!");
        }
    }
            
    public void LoadCaptureData() throws FileNotFoundException{
        String CaptureData = "";
        try{
            File DATA = new File(fileLocation);
            try (FileInputStream DATASTREAM = new FileInputStream(DATA); InputStreamReader INPUT = new InputStreamReader(DATASTREAM); BufferedReader IN = new BufferedReader(INPUT)) {                
                while(IN.read() != -1){
                    CaptureData = CaptureData + IN.readLine();
                }
            }
            outputText.setText(CaptureData);
            JOptionPane.showMessageDialog(null, "Data Loaded successfully");            
        }catch(IOException X){
            JOptionPane.showMessageDialog(null, "File access error");
        }
    }
             
    public void ChooseInterface(int TEMP){    
        try{
            if(TEMP > -1){
                INDEX = TEMP;
                BTN_CAPTURE.setEnabled(true);
                BTN_CAPTURE.setBackground(greenButtonColor);
            }
            else{
                JOptionPane.showMessageDialog(null,"Select valid interface");
            }
            TF_SelectInterface.setText("");
        }
        catch(NumberFormatException | HeadlessException Ex){
            JOptionPane.showMessageDialog(null, Ex);
        }
    }
    
    public void Action_B_Filter(ActionEvent X){
        try{
            if(RB_filter_enable.isSelected()){
                if(RB_port_HTTP.isSelected())
                    CAP.setFilter("port 80", true);
                else if(RB_port_FTP.isSelected())
                   CAP.setFilter("port 21", true);
                else if(RB_port_SMTP.isSelected())
                   CAP.setFilter("port 25", true);
                else if(RB_port_SAMBA.isSelected())
                   CAP.setFilter("port ", true);
                else if(RB_port_POP3.isSelected())
                   CAP.setFilter("port 110", true);
                else if(RB_port_IMAP.isSelected())
                   CAP.setFilter("port 143", true);
                else if(RB_port_IMAPS.isSelected())
                   CAP.setFilter("port 993", true);
                else if(RB_port_SSH.isSelected())
                   CAP.setFilter("port 22", true);
                else if(RB_port_Telnet.isSelected())
                   CAP.setFilter("port 23", true);
            }
            else
                JOptionPane.showMessageDialog(null,"Filetring is Disabled!");
        }
        catch(IOException | HeadlessException Y){
            System.out.print(Y);
        }
    }
    
    public void filtersEnable(){
        RB_port_HTTP.setVisible(true);
        RB_port_SSH.setVisible(true);
        RB_port_SSL.setVisible(true);
        RB_port_IMAP.setVisible(true);
        RB_port_IMAPS.setVisible(true);
        RB_port_FTP.setVisible(true);
        RB_port_SAMBA.setVisible(true);
        RB_port_Telnet.setVisible(true);
        RB_port_SQL.setVisible(true);
        RB_port_DNS.setVisible(true);
        RB_port_SMTP.setVisible(true);
        RB_port_POP3.setVisible(true);
        Filters_Selection.setVisible(true);
        RB_filter_enable.setVisible(true);
        RB_filter_disable.setVisible(true);
        filterEnDi.setVisible(true);
    }
    
    public void filtersDisable(){
        TF_SelectInterface.setVisible(false);
        RB_port_HTTP.setVisible(false);
        RB_port_SSH.setVisible(false);
        RB_port_SSL.setVisible(false);
        RB_port_IMAP.setVisible(false);
        RB_port_IMAPS.setVisible(false);
        RB_port_FTP.setVisible(false);
        RB_port_SAMBA.setVisible(false);
        RB_port_Telnet.setVisible(false);
        RB_port_SQL.setVisible(false);
        RB_port_DNS.setVisible(false);
        RB_port_SMTP.setVisible(false);
        RB_port_POP3.setVisible(false);
        Filters_Selection.setVisible(false);
        RB_filter_enable.setVisible(false);
        RB_filter_disable.setVisible(false);
        filterEnDi.setVisible(false);
    }   
}
