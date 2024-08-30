import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
@Getter
@Setter
public class PacketCatcher {

    /**
     * Статический блок инициализации
     * Выводит в лог доступные сетевые интерфейсы
     */
    static {
        try {
            for (PcapNetworkInterface nic : Pcaps.findAllDevs()) {
            log.info("found nic {}", nic);
            }
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }
    }

    private String nicName;
    private PcapHandle handle;
    private final List<Listener> packetListeners = new CopyOnWriteArrayList<>();


    /**
     * Реализация интерфейса, обрабатывающего полученные пакеты
     * Уведомляет слушателей
     */
    private final PacketListener defaultPacketListener = packet -> {
        decode(packet);
        packetListeners.forEach(Listener::listen);
    };


    public void process() throws PcapNativeException, NotOpenException {
        if (handle == null){
            initializeNetworkInterface();

            if (handle != null) {
                handle.setFilter("ether proto 0x88B8", BpfProgram.BpfCompileMode.NONOPTIMIZE); // Для GOOSE ???

                Thread captureThread = new Thread(() -> {
                    try {
                        log.info("Starting packet capture");
                        handle.loop(0, defaultPacketListener);
                    } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                        throw new RuntimeException(e);
                    }
                    log.info("Packet capture finished");
                });
                captureThread.start();

            }
        }
    }

    private void initializeNetworkInterface() throws PcapNativeException {
        Optional<PcapNetworkInterface> nic = Pcaps.findAllDevs().stream()
                .filter(i -> nicName.equals(i.getName()))  // Сравниваем имя интерфейса
                .findFirst();
        if (nic.isPresent()) {
            handle = nic.get().openLive(1500, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            log.info("Network Handler created: {}", nic.get().getName());
        } else {
            log.error("Network interface not found");
        }
    }

//    private void initializeNetworkInterface() throws PcapNativeException {
//        Optional<PcapNetworkInterface> nic = Pcaps.findAllDevs().stream()
//                .filter(i -> nicName.equals(i.getDescription()))
//                .findFirst();
//        if (nic.isPresent()) {
//            handle = nic.get().openLive(1500, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
//            log.info("Network Handler created: {}", nic);
//        } else {
//            log.error("Network interface not found");
//        }
//    }

    private static void writeToFile(GooseFrame gooseFrame) throws IOException {
        PrintWriter writer = new PrintWriter("DecodedFrames.txt", StandardCharsets.UTF_8);
        writer.println("Destination         :    " + gooseFrame.getDestination());
        writer.println("Source              :    " + gooseFrame.getSource());
        writer.println("Interface           :    " + gooseFrame.getInter());
        writer.println("GocbRef             :    " + gooseFrame.getGocbRef());
        writer.println("TimeAllowedToLive   :    " + gooseFrame.getTimeAllowedToLive());
        writer.println("DatSet              :    " + gooseFrame.getDatSet());
        writer.println("GoID                :    " + gooseFrame.getGoID());
        //timestamp
        writer.println("StNum               :    " + gooseFrame.getStNum());
        writer.println("SqNum               :    " + gooseFrame.getSqNum());
        //confRev
        //ndsCom
        writer.println("NumDatSetEntries    :    " + gooseFrame.getNumDatSetEntries());
        for (AllData dataPart: gooseFrame.getAllData()) {
            writer.println(dataPart.getType() + "   :   " + dataPart.getValue());
        }
        writer.close();
    }

    private static void writeToConsole(GooseFrame gooseFrame) {
        System.out.println("Destination         :    " + gooseFrame.getDestination());
        System.out.println("Source              :    " + gooseFrame.getSource());
        System.out.println("Interface           :    " + gooseFrame.getInter());
        System.out.println();

        System.out.println("GocbRef             :    " + gooseFrame.getGocbRef());
        System.out.println("                         "+ Arrays.toString(GooseFrame.convertToHex(gooseFrame.getGocbRef().getBytes(StandardCharsets.UTF_8))));
        System.out.println();

        System.out.println("TimeAllowedToLive   :    " + gooseFrame.getTimeAllowedToLive());
        System.out.println("                         "+ Arrays.toString(GooseFrame.convertToHex(ByteBuffer.allocate(4).putInt(gooseFrame.getTimeAllowedToLive()).array())));
        System.out.println();

        System.out.println("DatSet              :    " + gooseFrame.getDatSet());
        System.out.println("                         "+ Arrays.toString(GooseFrame.convertToHex(gooseFrame.getDatSet().getBytes(StandardCharsets.UTF_8))));
        System.out.println();

        System.out.println("GoID                :    " + gooseFrame.getGoID());
        System.out.println("                         "+ Arrays.toString(GooseFrame.convertToHex(gooseFrame.getGoID().getBytes(StandardCharsets.UTF_8))));
        System.out.println();

        System.out.println("Timestamp           :    " + gooseFrame.getTimestamp());
        System.out.println();

        System.out.println("StNum               :    " + gooseFrame.getStNum());
        System.out.println("                         "+ Arrays.toString(GooseFrame.convertToHex(ByteBuffer.allocate(4).putInt(gooseFrame.getStNum()).array())));
        System.out.println();

        System.out.println("SqNum               :    " + gooseFrame.getSqNum());
        System.out.println("                         "+ Arrays.toString(GooseFrame.convertToHex(ByteBuffer.allocate(4).putInt(gooseFrame.getSqNum()).array())));
        System.out.println();

        System.out.println("ConfRev             :    " + gooseFrame.getConfRev());
        System.out.println("                         "+ Arrays.toString(GooseFrame.convertToHex(ByteBuffer.allocate(4).putInt(gooseFrame.getConfRev()).array())));
        System.out.println();

        System.out.println("NdsCom              :    " + gooseFrame.isNdsCom());
        System.out.println();

        System.out.println("NumDatSetEntries    :    " + gooseFrame.getNumDatSetEntries());
        System.out.println();

        for (AllData dataPart: gooseFrame.getAllData()) {
            System.out.println(dataPart.getType() + "   :   " + dataPart.getValue());
        }
    }

    private void decode(Packet packet){
        try {
            byte[] data = packet.getRawData();

            GooseFrame gooseFrame = new GooseFrame();
            gooseFrame.parseGooseFrame(data);

            if (gooseFrame.getDestination() != null) {
                writeToConsole(gooseFrame);
                System.out.println(Arrays.toString(GooseFrame.convertToHex(data)));
                System.out.println();
                System.out.println();
                System.out.println();
                System.out.println();
            }


            //System.out.println(Arrays.toString(data));
        } catch (Exception e) {log.error("Cannot parse goose frame");}
    }

}
