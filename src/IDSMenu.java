import java.util.Scanner;

public class IDSMenu {

    public static void main(String[] args){
        Scanner scanner = new Scanner(System.in);
        boolean flag = true;
        while (flag) {
            System.out.print("\n----------JAVA IDS MENU----------\n1. Analyze malicious traffic\n2. Analyze normal traffic" +
            "\n3. Analyze realistic traffic\n4. Analyze a custom CSV file\n5. Run automated tests\n0. Exit\nEnter your choice: ");
            int num = scanner.nextInt();
            switch (num) {
                case 1:
                    System.out.println("\nAnalyzing malicious traffic ");
                    Main.main(new String[]{"data/network_events.csv"});
                    break;
                case 2:
                    System.out.println("\nAnalyzing normal traffic ");
                    Main.main(new String[]{"data/normal_events.csv"});
                    break;
                case 3:
                    System.out.println("\nAnalyzing realistic traffic ");
                    Main.main(new String[]{"data/realistic_events.csv"});
                    break;
                case 4:
                    System.out.print("\nEnter the path to your CSV file: ");
                    scanner.nextLine();
                    String filePath = scanner.nextLine().trim();
                    System.out.println("\nAnalyzing custom traffic from: " + filePath);
                    Main.main(new String[]{filePath});
                    break;
                case 5:
                    System.out.println("\nRunning automated tests ");
                    //IDSTest.runTests();
                    break;
                case 0:
                    flag = false;
                    System.out.println("\nExiting the program.");
                    scanner.close();
                    break;
                default:
                    System.out.println("\nInvalid choice. Please try again.");
                    break;
            }
        }
    }
}