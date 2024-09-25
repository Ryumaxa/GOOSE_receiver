import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Getter @Setter
public class GooseParser {
    private String destination;
    private String source;
    private String inter;
    private String gocbRef;
    private int timeAllowedToLive;
    private String datSet;
    private String goID;
    private String timestamp;
    private int stNum;
    private int sqNum;
    private boolean simulation;
    private int confRev;
    private boolean ndsCom;
    private int numDatSetEntries;
    private List<Object[]> allData;
    private int frameLength;
    private String sourceAddress;

    public GooseParser(String sourceAddress) {
        this.allData = new ArrayList<>();
        this.sourceAddress = sourceAddress;
    }

    public void parseGooseFrame(byte[] gooseFrame) {
        int index = 0;

        this.destination = parseMacAddress(gooseFrame, index);
        index += 6;

        this.source = parseMacAddress(gooseFrame, index);
        index += 6;

        if (!this.source.equals(sourceAddress)) {
            this.source = null;
            return;
        }

        this.inter = parseEtherType(gooseFrame, index);
        index += 2;

        while (index < gooseFrame.length) {
            int tag = gooseFrame[index++] & 0xFF;
            int length = parseLength(gooseFrame, index);
            index += length > 127 ? 2 : 1;

            switch (tag) {
                case 0x80:
                    index += 11;
                    length = 24;
                    parseStringField(gooseFrame, index, 24, "gocbRef");
                    break;
                case 0x81: this.timeAllowedToLive = parseInt(gooseFrame, index, length); break;
                case 0x82: parseStringField(gooseFrame, index, length, "datSet"); break;
                case 0x83: parseStringField(gooseFrame, index, length, "goID"); break;
                case 0x84: parseTimestamp(gooseFrame, index); break;
                case 0x85: this.stNum = parseInt(gooseFrame, index, length); break;
                case 0x86: this.sqNum = parseInt(gooseFrame, index, length); break;
                case 0x87: this.simulation = (gooseFrame[index] & 0xFF) != 0; break;
                case 0x88: this.confRev = gooseFrame[index] & 0xFF; break;
                case 0x89: this.ndsCom = (gooseFrame[index] & 0xFF) != 0; break;
                case 0x8A: this.numDatSetEntries = gooseFrame[index] & 0xFF; break;
                case 0xAB: parseAllData(Arrays.copyOfRange(gooseFrame, index, index + length)); break;
                default: break;
            }
            index += length;
        }
    }

    private void parseAllData(byte[] rawData) {
        int index = 0;

        while (index < rawData.length) {
            int tag = rawData[index++] & 0xFF;
            int length = parseLength(rawData, index);
            index += length > 127 ? 2 : 1;

            switch (tag) {
                case 0x83: allData.add(new Object[]{"Boolean", (rawData[index] & 0xFF) != 0}); break;
                case 0x84: allData.add(new Object[]{"String", decodeAndGetBitString(rawData, index, length)}); break;
                case 0x85:
                    if (length == 1) {
                        allData.add(new Object[]{"Integer", parseInt(rawData, index, length)});
                    } else {
                        allData.add(new Object[]{"Timestamp", intToUTC(parseInt(rawData, index, length))});
                    }
                    break;
                default: allData.add(new Object[]{"Unknown", null}); break;
            }
            index += length;
        }
    }

    private String parseMacAddress(byte[] data, int start) {
        StringBuilder mac = new StringBuilder(18);
        for (int i = start; i < start + 6; i++) {
            mac.append(String.format("%02X%s", data[i], (i < start + 5) ? ":" : ""));
        }
        return mac.toString();
    }

    private String parseEtherType(byte[] data, int start) {
        return String.format("%04x", ((data[start] & 0xFF) << 8) | (data[start + 1] & 0xFF));
    }

    private int parseLength(byte[] data, int index) {
        if ((data[index] & 0x80) != 0) {
            int lengthOfLength = data[index] & 0x7F;
            int length = 0;
            for (int i = 0; i < lengthOfLength; i++) {
                length = (length << 8) | (data[index + i + 1] & 0xFF);
            }
            return length;
        } else {
            return data[index] & 0xFF;
        }
    }

    private int parseInt(byte[] data, int index, int length) {
        int value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (data[index + i] & 0xFF);
        }
        return value;
    }

    private void parseStringField(byte[] data, int index, int length, String fieldName) {
        String value = new String(data, index, length, StandardCharsets.UTF_8);
        switch (fieldName) {
            case "gocbRef": this.gocbRef = value; break;
            case "datSet": this.datSet = value; break;
            case "goID": this.goID = value; break;
        }
    }

    private String decodeAndGetBitString(byte[] rawData, int index, int length) {
        byte[] bitStringData = Arrays.copyOfRange(rawData, index, index + length);
        int paddingBits = bitStringData[0] & 0xFF;

        StringBuilder bitString = new StringBuilder();
        for (int i = 1; i < bitStringData.length; i++) {
            String byteString = String.format("%8s", Integer.toBinaryString(bitStringData[i] & 0xFF)).replace(' ', '0');
            if (i == bitStringData.length - 1) {
                bitString.append(byteString, 0, 8 - paddingBits);
            } else {
                bitString.append(byteString);
            }
        }

        char[] bitsOfBitString = bitString.toString().toCharArray();
        StringBuilder qualityInfo = new StringBuilder();

        switch ("" + bitsOfBitString[0] + bitsOfBitString[1]) {
            case "00": qualityInfo.append("Validity: Good; "); break;
            case "01": qualityInfo.append("Validity: Invalid; "); break;
            case "11": qualityInfo.append("Validity: Questionable; "); break;
            default: qualityInfo.append("Validity: Unknown; "); break;
        }
        boolean state;
        for (int i = 2; i <= 12; i++) {
            state = (bitsOfBitString[i] == 1);
            String attributeName;
            switch (i) {
                case 2: attributeName = "Overflow"; break;
                case 3: attributeName = "OutOfRange"; break;
                case 4: attributeName = "BadReference"; break;
                case 5: attributeName = "Oscillatory"; break;
                case 6: attributeName = "Failure"; break;
                case 7: attributeName = "OldData"; break;
                case 8: attributeName = "Inconsistent"; break;
                case 9: attributeName = "Inaccurate"; break;
                case 10: attributeName = "Source"; break;
                case 11: attributeName = "Test"; break;
                case 12: attributeName = "OperatorBlocked"; break;
                default: attributeName = "Unknown"; break;
            }
            qualityInfo.append(attributeName).append(": ").append(state).append("; ");
        }
        return bitString + " (" + qualityInfo + ")";
    }


    private String intToUTC(int time) {
        Instant instant = Instant.ofEpochSecond(time);
        LocalDateTime dateTime = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
        return dateTime.format(DateTimeFormatter.ofPattern("MMM d, yyyy HH:mm:ss 'UTC'"));
    }

    private void parseTimestamp(byte[] data, int index) {
        long secondsSinceEpoch = ByteBuffer.wrap(data, index, 4).getInt() & 0xFFFFFFFFL;
        int fractionalPart = ((data[index + 4] & 0xFF) << 16) | ((data[index + 5] & 0xFF) << 8) | (data[index + 6] & 0xFF);
        double fractionalSeconds = fractionalPart / (double) (1 << 24);

        byte qualityByte = data[index + 7];
        String qualityInfo = decodeQuality(qualityByte);

        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calendar.setTimeInMillis((long) ((secondsSinceEpoch + fractionalSeconds) * 1000));
        String timestamp = String.format("%1$tb %1$te, %1$tY %1$tH:%1$tM:%1$tS.%2$06d UTC", calendar, (int) (fractionalSeconds * 1_000_000));
        this.timestamp = String.format("Timestamp: %s, Quality: %s", timestamp, qualityInfo);
    }

    private String decodeQuality(byte qualityByte) {
        StringBuilder quality = new StringBuilder();
        quality.append("Leap Second Known: ").append((qualityByte & 0x80) != 0).append(", ");
        quality.append("Clock Failure: ").append((qualityByte & 0x40) != 0).append(", ");
        quality.append("Clock not synchronized: ").append((qualityByte & 0x20) != 0).append(", ");
        int accuracy = qualityByte & 0x1F;
        if (accuracy == 31) {
            quality.append("Accuracy: Unspecified");
        } else if (accuracy >= 25) {
            quality.append("Accuracy: Invalid");
        } else {
            quality.append("Accuracy Bits: ").append(accuracy);
        }
        return quality.toString();
    }

}
