
package jpcap;

import jpcap.packet.Packet;

public class jpcap_capture implements PacketReceiver{
    public void recievePacket(Packet packet){
        MainProgram.outputText.append(packet.toString()+"\n-------------------------------------------------"+"-------------------------------------------------\n\n");
    }

    @Override
    public void receivePacket(Packet packet) {
          MainProgram.outputText.append(packet.toString()+"\n-------------------------------------------------"+"-------------------------------------------------\n\n");
    }
}