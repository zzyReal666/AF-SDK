package com.af.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BytesBufferTest {


    @Test
    void resize() {
        BytesBuffer buf = new BytesBuffer();
        buf.append(new byte[0]);
    }
}