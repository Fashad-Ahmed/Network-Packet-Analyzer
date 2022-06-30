package jpcap;

import java.awt.Color;
import java.awt.Font;
import java.awt.HeadlessException;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.WindowConstants;
import javax.swing.border.Border;

public class MACMod {
    static int macCount=17;
    static int z = 0;
    static int a=0;
    static char[] m;
    static String gatewayIP="";
    static String myMac="";
    static String macMasterFolder="D:\\IDS\\MacFolder";
    static String macResultFolder="D:\\IDS\\TestData";
    static String macMasterFile="D:\\IDS\\MacFolder\\MasterFile.txt";
    static String macSlaveFile="D:\\IDS\\MacFolder\\SlaveMacFile.txt";
    static String iPSavedFile="D:\\IDS\\MacFolder\\SlaveIPFile.txt";
    static String macRawFile="D:\\IDS\\MacFolder\\RawFile.txt";
    static String commonMacFile="D:\\IDS\\TestData\\Common Mac.txt";
    static String differentMacFile="D:\\IDS\\TestData\\Diff Mac.txt";
    static String tempDiffMacFile="D:\\IDS\\TestData\\Diff Mac Temp.txt";
    static String diffMacNEw="D:\\IDS\\TestData\\Diff Mac Temp New.txt";
    static String tempMac="";
    
    static final int mainFrameWidth=420;
    static final int mainFrameHeight=300;
    
    static int scrollPaneWidth=mainFrameWidth-7;
    static int scrollPaneHeight=mainFrameHeight-100;
    
    static int iPCount=0;
    static int macCountAll=0;
    
    static int masterCount=0;
    static int masterCountTotal=0;
    static int slaveCount=0;
    static int slaveCountTotal=0;
    
    static int j=0;
    
    static boolean diffStat=false;
    static boolean intruderStat=false;
    
    static JFrame mainFrame = new JFrame("Intruder Alert");
    static JScrollPane scrollarea = new JScrollPane();
    
    static JButton addToMasterFileBtn = new JButton("Add");
    static JButton exitBtn = new JButton("Exit");
    
    static JTextArea intrudersList = new JTextArea();
    static JTextField addMac = new JTextField();
    
    static int addMacTextBoxLeft=13;
    
    static final int textBoxFromRight=150;
    static int addBtnLeft=20+textBoxFromRight;
    
    static int btnFromTop=220;
    static int btnFromRight=55;
    static int btnFromBottom=20;
    
    static Border border = BorderFactory.createLineBorder(Color.BLACK, 1);

    public static List<String> listMacDiff = new ArrayList<>();
    public static List<String> listMac = new ArrayList<>();
    public static List<String> listIP = new ArrayList<>();
    
    static int IPMacNumber = 0;
    
    /**
     * @throws java.io.IOException
     */
    public static void start() throws IOException {
        makeDirectory();
        cleanFiles();
        getGateway();
        getMyMac();
        createRawFile();
        getMAC();
        getIP();
        intruderStat=false;
        macCompare();
    }
    
    public static void makeDirectory(){
        File macMaster = new File(macMasterFolder);
	if (!macMaster.exists()) 
            macMaster.mkdirs();
        File macResult = new File(macResultFolder);
	if (!macResult.exists()) 
            macResult.mkdirs();
    }
    
    public static void cleanFiles(){
        try{
            File masterFile=new File(macMasterFile);
                if(!masterFile.exists()) masterFile.createNewFile();
            File rawFile=new File(macRawFile);
                if(rawFile.exists()) rawFile.delete();
            File slaveFile=new File(macSlaveFile);
                if(slaveFile.exists()) slaveFile.delete();
            File comMacFile=new File(commonMacFile);
                if(comMacFile.exists()) comMacFile.delete();
            File difMacFile=new File(differentMacFile);
                if(difMacFile.exists()) difMacFile.delete();
            File iPFile=new File(iPSavedFile);
                if(iPFile.exists()) iPFile.delete();
            File newDiffFile=new File(diffMacNEw);
                if(newDiffFile.exists()) newDiffFile.delete();
            rawFile.createNewFile();
            slaveFile.createNewFile();
            comMacFile.createNewFile();
            difMacFile.createNewFile();
            iPFile.createNewFile();
            newDiffFile.createNewFile();
        }catch(Exception ex){
            JOptionPane.showMessageDialog(null, ex.toString());
        }
    }
    
    public static void getGateway(){
       try{
            String command = "ipconfig /all";
            Process p = Runtime.getRuntime().exec(command);

            BufferedReader bufferRead = new BufferedReader(new InputStreamReader(p.getInputStream()));
            Pattern pattern = Pattern.compile(".*Default Gateway.*: (.*)");

            while (true) {
                 String line = bufferRead.readLine();

                 if (line == null)
                     break;

                 Matcher match = pattern.matcher(line);
                 if (match.matches()) {
                     if(!"".equals(match.group(1).toString()))
                            gatewayIP=match.group(1);
                 }
             }
        }catch(Exception ex){
            JOptionPane.showMessageDialog(null, ex.toString());
        }
    }
    
    public static void getMyMac(){
       try{
           String command = null;
            if(System.getProperty("os.name").equals("Linux"))
                command = "ifconfig";
            else
                command = "getmac";
            Runtime r = Runtime.getRuntime();
            Process p = r.exec(command);
            Scanner s = new Scanner(p.getInputStream());
 
            StringBuilder sb = new StringBuilder("");
            while(s.hasNext())
                sb.append(s.next());
            String ipconfig = sb.toString();
            Pattern pt = Pattern.compile("([0-9A-F]{2}[:-]){5}([0-9A-F]{2})\\\\Device\\\\Tcpip(.*)");
            Matcher mt = pt.matcher(ipconfig);
            mt.find();
            String macAddr="";
            char[] dummyData = mt.group().toCharArray();
            for(int e=0;e<macCount;e++){
                if(dummyData[e]=='-') dummyData[e]=':';
                macAddr+=dummyData[e];
            }
            myMac=macAddr;
        }catch(Exception ex){
            JOptionPane.showMessageDialog(null, ex.toString());
        }
    }
    
    public static void createRawFile(){
        try {
            Process process = Runtime.getRuntime().exec("nmap -sP "+gatewayIP+"/24");
            BufferedReader bufferRead = new BufferedReader(new InputStreamReader(process.getInputStream()));
            
            while(true){
                String line = bufferRead.readLine();
                if (line == null)
                    break;
                else
                    try(PrintWriter saveNET = new PrintWriter(new BufferedWriter(new FileWriter(macRawFile, true)))){
                        saveNET.println(line);
                    }catch(Exception ex){
                        JOptionPane.showMessageDialog(null, ex.toString());
                    }
            }
        }catch(IOException | HeadlessException e){
                    
        }
    }
    
    public static void getMAC() throws IOException{
        try{
            BufferedReader bufferReadRAWFile = new BufferedReader(new FileReader(macRawFile));            
            Pattern macPattern = Pattern.compile(".*MAC Address:*.(.*)");
            
            while (true) {
                String line = bufferReadRAWFile.readLine();

                if (line == null)
                    break;

                Matcher mm = macPattern.matcher(line);
                if (mm.find()) {
                    try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(macSlaveFile, true)))) {
                        m=(mm.group(1)).toCharArray();
                        for(j=0;j<macCount;j++)
                            tempMac+=m[j];
                        out.println(tempMac);              
                        listMac.add(tempMac);
                        tempMac="";
                        macCountAll++;
                        out.close();
                    }catch (IOException ex) {
                        JOptionPane.showMessageDialog(null, ex.toString());
                    }
                }
            }
            try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(macSlaveFile, true)))) {
                out.println(myMac);              
                macCountAll++;
                out.close();
            }catch (IOException ex) {
                JOptionPane.showMessageDialog(null, ex.toString());
            }
            bufferReadRAWFile.close();
        }
        catch (IOException e) {
        }
    }
    
    public static void getIP() throws IOException{
        try{
            BufferedReader bufferReadIP = new BufferedReader(new FileReader(macRawFile));

            Pattern patternIP = Pattern.compile(".*Nmap scan report for * (.*)");

            while (true) {
                String line = bufferReadIP.readLine();

                if (line == null)
                    break;

                Matcher mm = patternIP.matcher(line);
                if (mm.find()) {
                    try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(iPSavedFile, true)))) {
                        String iPWrite=mm.group(1);
                        listIP.add(iPWrite);
                        out.println(iPWrite);
                        iPCount++;
                    }catch (IOException ex) {
                        JOptionPane.showMessageDialog(null, ex.toString());
                    }
                }
            }
            bufferReadIP.close();                    
        }catch(IOException | HeadlessException ex){
            JOptionPane.showMessageDialog(null, ex.toString());
        }
    }
    
    public static void macCompare() throws IOException{
        commonMac();
        diffMac();
//        macDiff();
        if(intruderStat==true) intruderAlert();
        else
            JOptionPane.showMessageDialog(null, "No Intruders.");
    }
    
    public static void commonMac() throws IOException{
        try {
            File fin1 = new File(macSlaveFile);
            File fin2 = new File(macMasterFile);
            
            FileInputStream fis1 = new FileInputStream(fin1);
            BufferedReader br1 = new BufferedReader(new InputStreamReader(fis1));
            String slaveLine;

            while ((slaveLine = br1.readLine()) != null) {
                String masterLine;
                FileInputStream fis2;
                fis2 = new FileInputStream(fin2);
                BufferedReader br2 = new BufferedReader(new InputStreamReader(fis2));
                while ((masterLine = br2.readLine()) != null)
                    if(slaveLine.equalsIgnoreCase(masterLine)){ 
                        try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(commonMacFile, true)))) {
                            out.println(slaveLine);
                        }catch (IOException e) {
                        }
                    }
            }
            br1.close();
            fis1.close();
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null, ex.toString());
        }
        PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(differentMacFile, true)));
        out.close();
    }
    
    @SuppressWarnings("empty-statement")
    public static void diffMac(){
        File commonMac = new File(commonMacFile);
        File tempFile = new File(differentMacFile);
        try{
            BufferedReader commonReader = new BufferedReader(new FileReader(commonMac));
            PrintWriter writer = new PrintWriter(new FileWriter(tempFile,true));
            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(differentMacFile)));
            String readline;
            String temp;
            int i=0;
            int l=0;
            boolean common = false;

            List<String> list = new ArrayList<>();
            while((temp = commonReader.readLine()) != null){
                list.add(temp);
                i++;
            }
            try (BufferedReader slaveReader = new BufferedReader(new FileReader(new File(macSlaveFile)))) {
                while((readline=slaveReader.readLine())!=null){
                    for(j=0;j<i;j++)
                        if((readline.equalsIgnoreCase(list.get(j)))) {
                            common= true;
                            break ;
                        }
                        else common=false;

                    if(common==false){
                            l++;
                            out.println(readline);
                            intruderStat = true;
                        }
                }
                slaveReader.close();
            }
            out.close();
            commonReader.close();
            writer.close();

            String temporary;
            
            BufferedReader readDiffToString = new BufferedReader(new FileReader(new File(differentMacFile)));
//            -------------------------------------------------
//            for(int tempo=0;tempo<100;tempo++)
//                listMacDiff.remove(tempo);
//            -------------------------------------------------
            while((temporary = readDiffToString.readLine()) != null){
                listMacDiff.add(temporary);
                a++;
            }
            readDiffToString.close();
            commonReader.close();
            writer.close();
            
        }catch(Exception ex){
            JOptionPane.showMessageDialog(null, ex.toString());
        }
    }
    
    public static void intruderAlert(){
        GUIBuildUp();
    }
    
    public static void GUIBuildUp(){
//           ----------------------Main Window-----------------------------
        mainFrame.setSize(mainFrameWidth,mainFrameHeight-25);
        mainFrame.setLocation(350, 150);
        mainFrame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        mainFrame.setResizable(false);
        mainFrame.getContentPane().setLayout(null);        
        
//        ----------------------Scroll Panel-----------------------------        
        scrollarea.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollarea.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollarea.setViewportView(intrudersList);       
        scrollarea.setBounds(1, 1, scrollPaneWidth, scrollPaneHeight+10);
        mainFrame.getContentPane().add(scrollarea); 
        
//        ----------------------Intruder List-----------------------------                
        intrudersList.setEditable(false);
        intrudersList.setBackground(Color.LIGHT_GRAY);
        intrudersList.setForeground(new Color(193, 54, 0));
        intrudersList.setFont(new Font("Times New Roman",1,20));
        intrudersList.setLineWrap(false);
        intruderListShow();
        
//      --------------------------------Selection------------------------------------
        mainFrame.getContentPane().add(addMac);
        addMac.setVisible(true);
        addMac.requestFocus();
        addMac.setBorder(border);
        addMac.setHorizontalAlignment(SwingConstants.CENTER);
        addMac.setMargin(new Insets(0,0,0,0));
        addMac.setBounds(addMacTextBoxLeft, btnFromTop, textBoxFromRight, btnFromBottom);
        
//        ----------------------Add Button-----------------------------        
        addToMasterFileBtn.setMargin(new Insets(0,0,0,0));
        addToMasterFileBtn.setBackground(MainProgram.greenButtonColor);
        addToMasterFileBtn.addActionListener((ActionEvent X) -> {
            try {
                addMacToMasterFile(X);
            } catch (IOException ex) {
                Logger.getLogger(MACMod.class.getName()).log(Level.SEVERE, null, ex);
            }
        });
        mainFrame.getContentPane().add(addToMasterFileBtn);
        addToMasterFileBtn.setBounds(addBtnLeft,btnFromTop,btnFromRight,btnFromBottom);
        
//        ----------------------Exit Button-----------------------------        
        exitBtn.setMargin(new Insets(0,0,0,0));
        exitBtn.setForeground(MainProgram.whiteColor);
        exitBtn.setBackground(MainProgram.redColorStatus);
        exitBtn.addActionListener((ActionEvent X) -> {
            try {
                exitBtnClicked(X);
            } catch (IOException ex) {
                Logger.getLogger(MACMod.class.getName()).log(Level.SEVERE, null, ex);
            }
        });
        mainFrame.getContentPane().add(exitBtn);
        exitBtn.setBounds(addBtnLeft+180,btnFromTop,btnFromRight,btnFromBottom);
        
        mainFrame.setVisible(true);   
    }
    
    public static void addMacToMasterFile(ActionEvent X) throws IOException{
        String get;                //txtbx
        String addedMac = null;    //addedmac
        try{
            if(!"".equals(get=addMac.getText())){
                try{
                    int macId;
                    macId=Integer.parseInt(get)-1;
                    if(macId<z){ 
                        addedMac=listMacDiff.get(macId);
                        System.out.println(addedMac);
                        PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(macMasterFile, true)));
                        out.println(addedMac);
                        JOptionPane.showMessageDialog(null, addedMac+" added to safe state.");
                        addMac.setText(null);
                        out.close();
                    }else{
                        addMac.setText("");
                    }
                }catch(NumberFormatException | IOException | HeadlessException ex){
                    addedMac=get;
                    addedMac=addedMac.replaceAll("\\s+","");
                    System.out.println(addedMac);
                    PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(macMasterFile, true)));
                    out.println(addedMac);
                    JOptionPane.showMessageDialog(null, addedMac+" added to safe state.");
                    addMac.setText(null);
                    out.close();
                }
            }
        }catch (IOException e) {
            JOptionPane.showMessageDialog(null, e);
        }
        intrudersList.setText("");
        intruderListShow();
    }
    
    public static void exitBtnClicked(ActionEvent X) throws IOException{
        listMacDiff.clear();
        z=0;
        cleanMasterFile.readMac();
        mainFrame.dispose();
    }
    
    public static void intruderListShow(){
        diffMac();
        try{
            z=0;
            String temp;
            String ipTemp;
            String macTemp;
            
            intrudersList.setText("");
            int ipInc=0;
            
            BufferedReader ipRead;
            BufferedReader macRead;
            try (BufferedReader intrudeRead = new BufferedReader(new FileReader(differentMacFile))) {
                ipRead = new BufferedReader(new FileReader(iPSavedFile));
                macRead = new BufferedReader(new FileReader(macSlaveFile));
                List<String> ipList = new ArrayList<>();
                while((ipTemp = ipRead.readLine()) != null){
                    ipList.add(ipTemp);
                    ipInc++;
                }   
                List<String> macList = new ArrayList<>();
//                -----------------------------------------------------------------------------
//                macList.clear();
//                -----------------------------------------------------------------------------
                while((macTemp = macRead.readLine()) != null){
                    macList.add(macTemp);
                }   
                String macIP="";
                while((temp=intrudeRead.readLine())!=null){
                    for(int f=0;f<ipInc;f++)
                        if(temp.equals(macList.get(f))){
                            macIP=ipList.get(f);
                            break;
                        }
                    z++;
                    intrudersList.append(z+".  "+temp+"\t"+macIP+"\n");
                    listMacDiff.add(temp);
                    System.out.println(listMacDiff.get(z));
                }   
                intrudeRead.close();
            }
            ipRead.close();
            macRead.close();
        }catch(Exception ex){
            JOptionPane.showMessageDialog(null, ex.toString());
        }
    }
    
    public static void macDiff() throws FileNotFoundException, IOException{
        String masterMac;
        String slaveMac;
        String writeMac;
        String tempMacList;
        int macCountNew=0;
        boolean commonMacTrue=false;
        
        BufferedReader readMaster = new BufferedReader(new FileReader(macMasterFile));
        BufferedReader readSlave = new BufferedReader(new FileReader(macSlaveFile));
        List<String> masterMacList=new ArrayList<>();
        while((masterMac=readMaster.readLine())!=null){
            masterMacList.add(masterMac);
            readMaster.close();
            macCountNew++;
        }
        readMaster.close();
        
        while((slaveMac=readSlave.readLine())!=null){
            for(int tempCount=0; tempCount<macCountNew; tempCount++){
                if(slaveMac.equals(masterMacList.get(tempCount))){
                    commonMacTrue=true;
                    break;
                }else commonMacTrue=false;
            }
            if(commonMacTrue==false){
                try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(new File(diffMacNEw))))){
                    out.println(slaveMac);
                    intruderStat=true;
                }
            }
        }
        readSlave.close();
        
        BufferedReader tempBuffer = new BufferedReader(new FileReader(new File(diffMacNEw)));
        while((tempMacList=tempBuffer.readLine())!=null){
            System.out.println(tempMacList);
        }
        tempBuffer.close();
    }
}