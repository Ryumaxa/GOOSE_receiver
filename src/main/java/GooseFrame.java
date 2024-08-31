import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Calendar;
import java.util.TimeZone;

@Getter @Setter
public class GooseFrame {

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
    private AllData allData;

    // Конструктор по умолчанию
    public GooseFrame() {
        this.allData = new AllData();
    }

    // Метод для парсинга GOOSE-фрейма
    public void parseGooseFrame(byte[] gooseFrame) {
        int index = 0;

        // Остановить парсинг, если устройство не подписано
        if (!parseMacAddress(gooseFrame, index).equals("01:0C:CD:04:00:22")) {
            return;
        }

        // 1. MAC адрес назначения (6 байт)
        this.destination = parseMacAddress(gooseFrame, index);
        index += 6;

        // 2. MAC адрес источника (6 байт)
        this.source = parseMacAddress(gooseFrame, index);
        index += 6;

        // 3. Тип EtherType (2 байта)
        this.inter = String.format("%04x", ((gooseFrame[index] & 0xFF) << 8) | (gooseFrame[index + 1] & 0xFF));
        index += 2;


        // Парсинг данных GOOSE PDU
        // Это основная часть обработки
        while (index < gooseFrame.length) {
            int tag = gooseFrame[index++] & 0xFF;
            int length = 0;


            // Обработка длины
            if ((gooseFrame[index] & 0x80) != 0) {
                int lengthOfLength = gooseFrame[index] & 0x7F;
                index++;
                for (int i = 0; i < lengthOfLength; i++) {
                    length = (length << 8) | (gooseFrame[index++] & 0xFF);
                }
            } else {
                length = gooseFrame[index++] & 0xFF;
            }

            switch (tag) {
                case 0x80:
                    index += 11; // Разобраться с костылем
                    length = length - 10; // Разобраться с костылем
                    this.gocbRef = new String(gooseFrame, index, length, StandardCharsets.UTF_8);
                    break;

                case 0x81:
                    // Колхоз, но работает (попробовать сдлать гибче и универсальнее)
                    if (gooseFrame[index-1] == 2) {
                        this.timeAllowedToLive = ((gooseFrame[index] & 0xFF) << 8) | (gooseFrame[index + 1] & 0xFF);
                    } else {
                        this.timeAllowedToLive = gooseFrame[index];
                    }
                    break;

                case 0x82:
                    this.datSet = new String(gooseFrame, index, length, StandardCharsets.UTF_8);
                    break;

                case 0x83:
                    this.goID = new String(gooseFrame, index, length, StandardCharsets.UTF_8);
                    break;

                case 0x84:
                    parseTimestamp(gooseFrame, index);
                    break;

                case 0x85:
                    this.stNum = ((gooseFrame[index] & 0xFF) << 8) | (gooseFrame[index + 1] & 0xFF);
                    break;

                case 0x86:
                    this.sqNum = gooseFrame[index] & 0xFF;
                    break;

                case 0x87:
                    this.simulation = (gooseFrame[index] & 0xFF) != 0;
                    break;

                case 0x88:
                    this.confRev = gooseFrame[index] & 0xFF;
                    break;

                case 0x89:
                    this.ndsCom = (gooseFrame[index] & 0xFF) != 0;
                    break;

                case 0x8A:
                    this.numDatSetEntries = gooseFrame[index] & 0xFF;
                    break;

                case 0xAB: // тут занимаемся датой
                    this.allData.parse(Arrays.copyOfRange(gooseFrame, index, index + length));
                    break;

                default:
                    break;
            }

            // Переход к следующему TLV блоку
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

//    private void parseTimestamp(byte[] gooseFrame, int index) {
//        ByteBuffer buffer = ByteBuffer.wrap(gooseFrame, index, 8);
//        buffer.order(ByteOrder.BIG_ENDIAN);  // Убедитесь, что порядок байтов правильный
//        long nanosSinceEpoch = buffer.getLong();
//
//        Instant instant = Instant.ofEpochSecond(0, nanosSinceEpoch);
//        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd, yyyy HH:mm:ss.nnnnnnnnn 'UTC'")
//                .withZone(ZoneOffset.UTC);
//
//        this.timestamp = formatter.format(instant);
//
//        // Вывод в байтах 16 для отладки
//        //this.timestamp = Arrays.toString(convertToHex(Arrays.copyOfRange(gooseFrame, index, index + 8)));
//    }

    private void parseTimestamp(byte[] gooseFrame, int index) {
        byte[] timeData = Arrays.copyOfRange(gooseFrame, index, index + 8);

        // Первые 4 байта — количество секунд с 01.01.1970
        ByteBuffer buffer = ByteBuffer.wrap(timeData, 0, 4);
        long secondsSinceEpoch = buffer.getInt() & 0xFFFFFFFFL;

        // Следующие 3 байта — дробная часть
        int fractionalPart = ((timeData[4] & 0xFF) << 16)
                | ((timeData[5] & 0xFF) << 8)
                | (timeData[6] & 0xFF);
        double fractionalSeconds = fractionalPart / (double) (1 << 24);

        // Последний байт — информация о качестве
        byte qualityByte = timeData[7];
        String qualityInfo = decodeQuality(qualityByte);

        // Получаем итоговое время с учетом дробной части
        double totalTime = secondsSinceEpoch + fractionalSeconds;

        // Преобразуем секунды с эпохи в календарное время
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calendar.setTimeInMillis((long) (totalTime * 1000));

        // Форматируем результат
        String timestamp = String.format("%1$tb %1$td, %1$tY %1$tH:%1$tM:%1$tS.%2$09d UTC", calendar, (int)(fractionalSeconds * 1_000_000_000L));
        this.timestamp = String.format("Timestamp: %s, Quality: %s", timestamp, qualityInfo);
    }

    private static String decodeQuality(byte qualityByte) {
        StringBuilder quality = new StringBuilder();

        quality.append("Leap Second Known: ").append((qualityByte & 0x80) != 0).append(", ");
        quality.append("Clock Failure: ").append((qualityByte & 0x40) == 0).append(", ");
        quality.append("Clock Synchronized: ").append((qualityByte & 0x20) == 0).append(", ");
        quality.append("Accuracy Bits: ").append(String.format("%05d", qualityByte & 0x1F));

        return quality.toString();
    }

    public static String[] convertToHex(byte[] decimalBytes) {
        String[] hexArray = new String[decimalBytes.length];
        for (int i = 0; i < decimalBytes.length; i++) {
            // Преобразование каждого байта в шестнадцатеричную строку
            hexArray[i] = String.format("%02X", decimalBytes[i]);
        }
        return hexArray;
    }

}
