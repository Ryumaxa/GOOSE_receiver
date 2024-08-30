import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AllData {
    private String type;
    private Object value;

    public void parse(byte[] data, int offset, int length) {
        // Прочитать тип данных (например, первый байт)
        int typeTag = data[offset] & 0xFF;
        this.type = determineType(typeTag);

        // Прочитать значение данных в зависимости от типа
        this.value = extractValue(data, offset + 1, length - 1, type);
    }

    private String determineType(int typeTag) {
        // Пример сопоставления типа данных с тегом
        switch (typeTag) {
            case 0x83:
                return "Boolean";
            case 0x85:
                return "Integer";
            case 0x84:
                return "String";
            // Добавьте другие типы по мере необходимости
            default:
                return "Unknown";
        }
    }

    private Object extractValue(byte[] data, int offset, int length, String type) {
        switch (type) {
            case "Boolean":
                return data[offset] != 0;
            case "Integer":
                return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
            case "String":
                return new String(data, offset, length);
            // Добавьте другие типы по мере необходимости
            default:
                return null;
        }
    }
}

