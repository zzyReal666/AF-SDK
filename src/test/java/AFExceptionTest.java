import com.af.exception.AFIOException;
import org.junit.jupiter.api.Test;


/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/19 17:36
 */
public class AFExceptionTest {
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AFExceptionTest.class);
    @Test
    public void testAFIOException() {
        try {
            throw new AFIOException("请求头转换为字节数组失败");
        } catch (AFIOException e) {
            logger.error("请求头转换为字节数组失败");
        }
    }
}
