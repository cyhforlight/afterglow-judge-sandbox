import java.util.*;

public class Main {
    public static void main(String[] args) {
        List<byte[]> data = new ArrayList<>();
        while (true) {
            data.add(new byte[1024 * 1024]);
        }
    }
}
