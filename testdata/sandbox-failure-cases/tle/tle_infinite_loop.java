public class Main {
    public static void main(String[] args) {
        long sum = 0;
        while (true) {
            sum += 1;
            sum *= 5;
            sum %= 1000000007L;
        }
    }
}
