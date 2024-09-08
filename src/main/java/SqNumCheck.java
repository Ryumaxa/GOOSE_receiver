import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;

@Getter @Setter
public class SqNumCheck {
    private String senderName;
    private int gottenSqNum;
    private HashMap<String, Integer> SqMap;

    public SqNumCheck() {
        this.SqMap = new HashMap<>();
    }

    public void gapCheck(String name, int sqNum) {
        Integer previousSqNum = this.SqMap.get(name);
        if (previousSqNum != null && sqNum != previousSqNum + 1 && sqNum != 0) {
            System.err.println("Сообщение от " + name + " было пропущено!");
        }
        this.SqMap.put(name, sqNum);
    }
}
