import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.Arrays;

@Getter @Setter
public class AllData {
    private ArrayList<Data> allData;

    public AllData() {
        this.allData = new ArrayList<>();
    }

    public void parse(byte[] rawData) {
        int index = 0;

        // Это основная часть обработки
        while (index < rawData.length) {
            int tag = rawData[index++] & 0xFF;
            int length = 0;


            // Обработка длины
            if ((rawData[index] & 0x80) != 0) {
                int lengthOfLength = rawData[index] & 0x7F;
                index++;
                for (int i = 0; i < lengthOfLength; i++) {
                    length = (length << 8) | (rawData[index++] & 0xFF);
                }
            } else {
                length = rawData[index++] & 0xFF;
            }

            switch (tag) {
                case 0x83:
                    this.allData.add(new Data("Boolean", (rawData[index] & 0xFF) != 0));
                    break;

                case 0x84:
                    StringBuilder bitString = getStringBuilder(rawData, index, length);

                    this.allData.add(new Data("String", bitString.toString()));
//                    this.allData.add(new Data("String", new String(rawData, index+1, length-1, StandardCharsets.UTF_8)));
                    break;

                case 0x85:
                    int val = ((rawData[index] & 0xFF) << 24) |
                            ((rawData[index + 1] & 0xFF) << 16) |
                            ((rawData[index + 2] & 0xFF) << 8) |
                            (rawData[index + 3] & 0xFF);
                    this.allData.add(new Data("Integer", val));
                    break;

                default:
                    this.allData.add(new Data("Unknown", null));
                    break;
            }

            // Переход к следующему TLV блоку
            index += length;
        }
    }

    private static StringBuilder getStringBuilder(byte[] rawData, int index, int length) {
        byte[] bitStringData = Arrays.copyOfRange(rawData, index, index + length);
        // Первый байт — это Padding, указывает на количество неиспользуемых битов в последнем байте
        int paddingBits = bitStringData[0] & 0xFF;

        StringBuilder bitString = new StringBuilder();
        for (int i = 1; i < bitStringData.length; i++) {
            String byteString = String.format("%8s", Integer.toBinaryString(bitStringData[i] & 0xFF)).replace(' ', '0');
            if (i == bitStringData.length - 1) { // Последний байт
                bitString.append(byteString, 0, 8 - paddingBits); // Отсекаем лишние биты
            } else {
                bitString.append(byteString);
            }
        }
        return bitString;
    }
}

