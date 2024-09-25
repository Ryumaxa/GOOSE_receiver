import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Slf4j @Getter @Setter
public class PacketCatcher {

    private PrintWriter writer;
    private String sourceAddress;
    private SqNumCheck sqNumCheck;
    private String nicName;
    private PcapHandle handle;

    public PacketCatcher(String sourceAddress) {
        this.sourceAddress = sourceAddress;
        sqNumCheck = new SqNumCheck();
        try {
            writer = new PrintWriter("DecodedFrames.txt", StandardCharsets.UTF_8);
            for (PcapNetworkInterface nic : Pcaps.findAllDevs()) {
                log.info("found nic {}", nic);
            }
        } catch (IOException e) {
            log.error("Failed to open file for writing", e);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }
    }

    private final PacketListener defaultPacketListener = this::decode;

    public void process() throws PcapNativeException, NotOpenException {
        if (handle == null){
            initializeNetworkInterface();

            if (handle != null) {
                handle.setFilter("ether proto 0x88B8", BpfProgram.BpfCompileMode.NONOPTIMIZE);

                Thread captureThread = new Thread(() -> {
                    try {
                        log.info("Starting packet capture");
                        handle.loop(0, defaultPacketListener);
                    } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                        throw new RuntimeException(e);
                    } finally {
                        closeWriter();
                    }
                    log.info("Packet capture finished");
                });
                captureThread.start();
            }
        }
    }

    private void initializeNetworkInterface() throws PcapNativeException {
        Optional<PcapNetworkInterface> nic = Pcaps.findAllDevs().stream()
                .filter(i -> nicName.equals(i.getName()))
                .findFirst();
        if (nic.isPresent()) {
            handle = nic.get().openLive(1500, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            log.info("Network Handler created: {}", nic.get().getName());
        } else {
            log.error("Network interface not found");
        }
    }

    private void writeToFile(GooseParser gooseFrame) {
        writer.println("Destination         :    " + gooseFrame.getDestination());
        writer.println("Source              :    " + gooseFrame.getSource());
        writer.println("Interface           :    " + gooseFrame.getInter());

        writer.println("GocbRef             :    " + gooseFrame.getGocbRef());
        writer.println("TimeAllowedToLive   :    " + gooseFrame.getTimeAllowedToLive());
        writer.println("DatSet              :    " + gooseFrame.getDatSet());
        writer.println("GoID                :    " + gooseFrame.getGoID());
        writer.println("Timestamp           :    " + gooseFrame.getTimestamp());
        writer.println("StNum               :    " + gooseFrame.getStNum());
        writer.println("SqNum               :    " + gooseFrame.getSqNum());
        writer.println("ConfRev             :    " + gooseFrame.getConfRev());
        writer.println("NdsCom              :    " + gooseFrame.isNdsCom());
        writer.println("NumDatSetEntries    :    " + gooseFrame.getNumDatSetEntries());

        for (Object[] data : gooseFrame.getAllData()) {
            writer.println(data[0] + "   :   " + data[1]);
        }
        writer.println("\n".repeat(4));
        writer.flush();
    }

    public void closeWriter() {
        if (writer != null) {
            writer.close();
        }
    }

    private void writeToConsole(GooseParser gooseFrame) {
        System.out.println("Destination         :    " + gooseFrame.getDestination());
        System.out.println("Source              :    " + gooseFrame.getSource());
        System.out.println("Interface           :    " + gooseFrame.getInter());

        System.out.println("GocbRef             :    " + gooseFrame.getGocbRef());
        System.out.println("TimeAllowedToLive   :    " + gooseFrame.getTimeAllowedToLive());
        System.out.println("DatSet              :    " + gooseFrame.getDatSet());
        System.out.println("GoID                :    " + gooseFrame.getGoID());
        System.out.println("Timestamp           :    " + gooseFrame.getTimestamp());
        System.out.println("StNum               :    " + gooseFrame.getStNum());
        System.out.println("SqNum               :    " + gooseFrame.getSqNum());
        System.out.println("ConfRev             :    " + gooseFrame.getConfRev());
        System.out.println("NdsCom              :    " + gooseFrame.isNdsCom());
        System.out.println("NumDatSetEntries    :    " + gooseFrame.getNumDatSetEntries());

        for (Object[] data : gooseFrame.getAllData()) {
            System.out.println(data[0] + "   :   " + data[1]);
        }
        System.out.println("\n".repeat(4));
    }

    private void decode(Packet packet){
        try {
            byte[] data = packet.getRawData();

            GooseParser gooseFrame = new GooseParser(sourceAddress);
            gooseFrame.parseGooseFrame(data);

            if (gooseFrame.getSource() != null) {
                sqNumCheck.gapCheck(gooseFrame.getGoID(), gooseFrame.getSqNum());
                writeToConsole(gooseFrame);
                writeToFile(gooseFrame);

            }
        } catch (Exception e) {log.error("Cannot parse goose frame");}
    }
}
