package com.af.utils;

/**
 * Interface for Memoable objects. Memoable objects allow the taking of a snapshot of their internal state
 * via the copy() method and then reseting the object back to that state later using the reset() method.
 */
public interface Memoable {
    Memoable copy();

    void reset(Memoable other);
}
