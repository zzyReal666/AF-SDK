import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.core.FileAppender;
import ch.qos.logback.core.util.StatusPrinter;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
*
* @author zhangzhongyuan@szanfu.cn
* @since  2023/4/17 16:33
* @description
*/
public class LogbackTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(LogbackTest.class);

    @Test
    public void testLogback() {
        LOGGER.debug("Debug log message");

        LOGGER.info("Info log message");

        LOGGER.warn("Warn log message");

        LOGGER.error("Error log message");


    }
    /**
     * change log level at runtime
     *
     */
    @Test
    public void testChangeLogLevel() {
        // change log level at runtime
        ch.qos.logback.classic.Logger root = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        root.setLevel(Level.WARN);
        LOGGER.debug("Debug log message");
        LOGGER.info("Info log message");
        LOGGER.warn("Warn log message");
        LOGGER.error("Error log message");

    }

    /**
     * 测试日志输出到文件
     */
    @Test
public void testLogToFile() {

        // get the logger context
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();

        // build the file appender
        FileAppender fileAppender = new FileAppender();
        fileAppender.setContext(context);
        fileAppender.setName("file");
        fileAppender.setFile("logs/myLogFile.log");

        // build the encoder
        PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setContext(context);
        encoder.setPattern("%d %p %c{1.} [%t] %m%n");
        encoder.start();

        // attach the encoder to the appender
        fileAppender.setEncoder(encoder);
        fileAppender.start();

        // get the logger for the example class

        // set the log level
        ch.qos.logback.classic.Logger rootLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        rootLogger.setLevel(Level.INFO);

        // add the appender to the logger
        rootLogger.addAppender(fileAppender);

        // log some messages
        LOGGER.debug("Debug message");
        LOGGER.info("Info message");
        LOGGER.warn("Warn message");
        LOGGER.error("Error message");

        // print logback status
        StatusPrinter.print(context);
    }

}