public class Dec {
  public static void main(String[] a) throws Exception {
    try {
      Object[] r = burp.Zu6.ZG(a[0], Integer.parseInt(a[1]));
      System.out.println("out0 type: " + (r[0] == null ? "null" : r[0].getClass().getName()));
      System.out.println("out0: " + r[0]);
      System.out.println("out1: " + r[1]);
    } catch (Throwable t) {
      System.out.println("THREW " + t.getClass().getName() + ": " + t.getMessage());
    }
  }
}
