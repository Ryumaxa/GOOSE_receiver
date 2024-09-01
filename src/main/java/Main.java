import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class Main {
    public static void main(String[] args) throws NotOpenException, PcapNativeException {

        Config config = ConfigReader.readConfig("сfg.xml");

        PacketCatcher packetCatcher = new PacketCatcher(config.getSource());
        packetCatcher.setNicName(config.getNetworkInterface());
        packetCatcher.process();
    }
}