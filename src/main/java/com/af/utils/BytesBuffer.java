package com.af.utils;

import java.io.Serializable;

/**
 * bytes数据缓冲区，取代数组， 注意：本类非线程安全
 *
 * @author linzhj
 * @date 2022年4月21日
 */
public class BytesBuffer implements Serializable {
    private static final long serialVersionUID = -2850208874997943712L;

    /**
     * 当前缓冲区
     */
    private byte[] buffer;
    /**
     * 当前缓冲区偏移量
     */
    private int offset;
    /**
     * 当前缓冲区初始容量
     */
    private final int initialCapacity;

    /**
     * 默认长度的缓冲区
     */
    public BytesBuffer() {
        this(1024);
    }

    /**
     * 指定长度的缓冲区
     */
    public BytesBuffer(int size) {
        initialCapacity = size;
        this.buffer = new byte[size];
    }

    /**
     * 初始数据转化为缓冲区
     */
    public BytesBuffer(byte[] array) {
        this.buffer = array;
        offset = array.length;
        initialCapacity = array.length;
    }

    /**
     * 扩充缓冲数组
     */
    private void resize(int appendSize) {
        if (buffer.length - offset > appendSize) {
            return; // 剩余缓冲足够用
        }
        byte[] tmp = buffer;
        buffer = new byte[buffer.length + Math.max(1024, appendSize)];
        System.arraycopy(tmp, 0, buffer, 0, offset);
    }

    /**
     * 当前缓冲区已有数据的字节数，并非缓冲区本身字节数
     */
    public int size() {
        return offset;
    }

    public boolean isEmpty() {
        return offset == 0;
    }

    public void reset() {
        offset = 0;
        buffer = new byte[initialCapacity];
    }

    /**
     * 返回缓冲区中的数据
     */
    public byte[] toBytes() {
        byte[] array = new byte[offset];
        System.arraycopy(buffer, 0, array, 0, offset);
        return array;
    }

    @Override
    public String toString() {
        return encodeHex(toBytes());
    }

    // -----------------------append方法-----------------------------------------

    /**
     * 追加数据
     *
     * @param array 数据
     * @param off   偏移量
     * @param len   字节数
     * @return 自身
     */
    public BytesBuffer append(byte[] array, int off, int len) {
        int end = off + len;
        if ((off < 0) || (len < 0) || (end > array.length)) {
            throw new IndexOutOfBoundsException();
        }
        if (len == 0) {
            return this;
        }
        resize(len);
        System.arraycopy(array, off, buffer, offset, len);
        offset = offset + len;
        return this;
    }

    /**
     * 追加数据
     */
    public BytesBuffer append(byte[] array) {
        if (array == null) {
            return this;
        }
        return append(array, 0, array.length);
    }

    /**
     * 追加一个字节
     */
    public BytesBuffer append(byte b) {
        resize(1);
        buffer[offset++] = b;
        return this;
    }

    /**
     * 追加四个字节的整型数据(以小端序转换)
     */
    public BytesBuffer append(int intValue) {
        resize(4);
        buffer[offset++] = (byte) (intValue & 0xFF);
        buffer[offset++] = (byte) ((intValue >> 8) & 0xFF);
        buffer[offset++] = (byte) ((intValue >> 16) & 0xFF);
        buffer[offset++] = (byte) ((intValue >> 24) & 0xFF);
        return this;
    }

    /**
     * 追加另一个缓冲区
     */
    public BytesBuffer append(BytesBuffer buff) {
        if (buff == null || buff.size() == 0) {
            return this;
        }
        append(buff.buffer, 0, buff.offset);
        return this;
    }

    // -----------------------read方法，从左向右读取，read完之后会移除这些数据-----------------------------------------

    /**
     * 读取1个字节
     */
    public byte read() {
        if (offset < 1) {
            throw new ArrayIndexOutOfBoundsException("缓冲区不足1字节，无法读取一个byte");
        }
        byte res = buffer[0];
        removeBytes(1);
        return res;
    }

    /**
     * 读取固定长度的字节数组
     */
    public byte[] read(int len) {
        if (offset < len) {
            throw new ArrayIndexOutOfBoundsException("缓冲区不足" + len + "字节，无法读取" + len + "长度的字节数组");
        }
        byte[] res = new byte[len];
        System.arraycopy(buffer, 0, res, 0, len);
        removeBytes(len);
        return res;
    }

    /**
     * 读取4个字节的int
     */
    public int readInt() {
        if (offset < 4) {
            throw new ArrayIndexOutOfBoundsException("缓冲区不足4字节，无法读取一个int");
        }
        int res = buffer[0] & 0xFF | (buffer[1] & 0xFF) << 8 | (buffer[2] & 0xFF) << 16 | (buffer[3] & 0xFF) << 24;
        removeBytes(4);
        return res;
    }

    /**
     * 读取固定长度的字节数组，并转成16进制字符串形式
     */
    public String readHex(int byteNumber) {
        return encodeHex(read(byteNumber));
    }

    /**
     * 先读取4个字节的int，再读取这个int长度的数据
     */
    public byte[] readOneData() {
        return read(readInt());
    }

    /**
     * 先读取4个字节的int，再读取这个int长度的数据
     */
    public String readOneHexData() {
        return encodeHex(readOneData());
    }

    // -----------------------get方法-----------------------------------------

    /**
     * 从缓冲区获取数据
     *
     * @param off 偏移量
     * @param len 字节数
     */
    public byte[] getBytes(int off, int len) {
        int end = off + len;
        if ((off < 0) || (len < 0) || (end > offset)) {
            throw new IndexOutOfBoundsException();
        }
        if (len == 0) {
            return new byte[0];
        }
        byte[] array = new byte[len];
        System.arraycopy(buffer, off, array, 0, len);
        return array;
    }

    /**
     * 从左起删除一定的字节数
     */
    private void removeBytes(int delNum) {
        byte[] remain = new byte[offset - delNum];
        System.arraycopy(buffer, delNum, remain, 0, remain.length);
        buffer = remain;
        offset = offset - delNum;
    }

    /**
     * 将字节数组转换为十六进制字符串
     *
     * @param data byte[]
     * @return 十六进制字符串
     */
    private static String encodeHex(byte[] data) {
        final char[] toDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        final int len = data.length;
        final char[] out = new char[len << 1];
        for (int i = 0, j = 0; i < len; i++) {
            out[j++] = toDigits[(0xF0 & data[i]) >>> 4];// 高位
            out[j++] = toDigits[0x0F & data[i]];// 低位
        }
        return new String(out);
    }

    public void clear() {
        buffer = new byte[0];
        offset = 0;
    }
}
