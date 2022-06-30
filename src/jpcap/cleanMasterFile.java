
package jpcap;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class cleanMasterFile {
    
    static List<String> readFromMasterFile = new ArrayList<>();
    static int macQty;
    static String tempMaster = "D:\\IDS\\MacFolder\\MasterFileTemp.txt";
    
    public static void readMac() throws FileNotFoundException, IOException{
        File master = new File(MACMod.macMasterFile);
        String tempMac;
        BufferedReader br = new BufferedReader(new FileReader(MACMod.macMasterFile));
        while((tempMac=br.readLine())!=null){
            readFromMasterFile.add(tempMac);
            macQty++;
        }
        br.close();
        master.delete();
        createMasterFile();
    }
    
    public static void createMasterFile() throws IOException{
        boolean common = false;
        int holder;
        List<String> tempHolder = new ArrayList<>();
        List<String> sorted = new ArrayList<>();
        try(PrintWriter write = new  PrintWriter(new BufferedWriter(new FileWriter(MACMod.macMasterFile)))) {
            for(holder=0; holder<macQty; holder++)
                tempHolder.add(readFromMasterFile.get(holder));
            try{
                int loop1;
                int loop2;
                for(loop1=0; loop1<macQty; loop1++){
                    for(loop2=loop1+1; loop2<macQty; loop2++){
                        if(tempHolder.get(loop1).equals(readFromMasterFile.get(loop2))){
                            common=true;
                            break;
                        }else common=false;
                    }
                    if(common!=true) sorted.add(tempHolder.get(loop1).replace("\\s+", ""));
                }
                
                for(holder=0;holder<macQty;holder++)
                    write.println(sorted.get(holder));
            }catch(Exception e){
            }
            write.close();
        }
    }
}
