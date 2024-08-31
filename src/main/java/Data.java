import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class Data {
    private String type;
    private Object value;

    public Data(String type, Object value) {
        this.type = type;
        this.value = value;
    }
}
