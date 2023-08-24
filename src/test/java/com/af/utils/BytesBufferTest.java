package com.af.utils;

import org.junit.jupiter.api.Test;

class BytesBufferTest {


    @Test
    void resize() {
        BytesBuffer buf = new BytesBuffer();
        buf.append(new byte[0]);
    }
}