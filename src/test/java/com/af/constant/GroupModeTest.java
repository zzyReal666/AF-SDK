package com.af.constant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GroupModeTest {


    @Test
    void testGetMode() {
        GroupMode groupMode = GroupMode.ECB;
        assertEquals("ECB", groupMode.getMode());
    }
}