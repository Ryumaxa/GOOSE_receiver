import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class Main {
    public static void main(String[] args) throws NotOpenException, PcapNativeException {
        ConfigReader configReader = new ConfigReader("cfg.xml");
        PacketCatcher packetCatcher = new PacketCatcher(configReader.getSource());
        packetCatcher.setNicName(configReader.getNetworkInterface());
        packetCatcher.process();
    }
}