package com.szaf.utils;

import com.szaf.exception.AFIOException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author zhangzhongyuan@szanfu.cn
 * @description
 * @since 2023/4/19 17:36
 */
public class AFExceptionTest {

    private static final Logger logger = LoggerFactory.getLogger(AFExceptionTest.class);
    @Test
    public void  testAFIOException(){
        try {
            throw new AFIOException("请求头转换为字节数组失败");
        }catch (AFIOException e){
            logger.error("请求头转换为字节数组失败",e);
        }
    }
}
