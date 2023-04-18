import com.af.socket.AFHsmInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/18 10:35
 */
public class LomBokTest {
    @Test
    public void testLombokBase() {
        AFHsmInfo hsmInfo = new AFHsmInfo("192.1268.xxx.xxx", 8008, "11111111");
        AFHsmInfo hsmInfo1 = new AFHsmInfo("192.1268.xxx.xxx", 8008, "11111111");
        System.out.println(hsmInfo);
        Assertions.assertEquals(hsmInfo, hsmInfo1);

    }
}
