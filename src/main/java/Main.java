import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class Main {
    public static void main(String[] args) throws NotOpenException, PcapNativeException {

        PacketCatcher packetCatcher = new PacketCatcher();
        packetCatcher.setNicName("awdl0");
        packetCatcher.process();
    }
}