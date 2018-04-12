package jpcap.packet;

import jpcap.JpcapCaptor;

/**
 * This is a root class of the all the packets captured by {@link JpcapCaptor Jpcap}.
 */
public class Packet implements java.io.Serializable {
    private static final long serialVersionUID = 5182709860137479561L;

    /**
     * Captured timestamp (sec)
     */
    public long sec;

    /**
     * Captured timestamp (micro sec)
     */
    public long usec;

    /**
     * Captured length
     */
    public int caplen;

    /**
     * Length of this packet
     */
    public int len;

    /**
     * Datalink layer header
     */
    public DatalinkPacket datalink;

    /**
     * Header data
     */
    public byte[] header;

    /**
     * Packet data (excluding the header)
     */
    public byte[] data;

    /**
     * Returned by JpcapCaptor.getPacket() when EOF was reached while reading from an offline file.
     */
    public static final Packet EOF = new Packet();

    void setPacketValue(long sec, long usec, int caplen, int len) {
        this.sec = sec;
        this.usec = usec;
        this.caplen = caplen;
        this.len = len;
    }

    void setDatalinkPacket(DatalinkPacket p) {
        datalink = p;
    }

    void setPacketData(byte[] data) {
        this.data = data;
    }

    void setPacketHeader(byte[] header) {
        this.header = header;
    }

    /**
     * Returns a string representation of this packet<BR>
     * Format: sec:usec
     *
     * @return a string representation of this packet
     */
    public String toString() {
        return sec + ":" + usec + " datalink:" + datalink.toString() + " ";
    }

    /**
     * 转换字节 高位 至 16进制(小写字母)
     * 
     * @param b
     * @return
     */
    private char hexUpperChar(byte b) {
        b = (byte) ((b >> 4) & 0xf);
        if (b == 0)
            return '0';
        else if (b < 10)
            return (char) ('0' + b);
        else
            return (char) ('a' + b - 10);
    }

    /**
     * 转换字节 低位 至 16进制(小写字母)
     * 
     * @param b
     * @return
     */
    private char hexLowerChar(byte b) {
        b = (byte) (b & 0xf);
        if (b == 0)
            return '0';
        else if (b < 10)
            return (char) ('0' + b);
        else
            return (char) ('a' + b - 10);
    }

    /**
     * 转换6位字节数组 至 00:ff:aa:0a:0f:f0 格式mac地址
     * 
     * @param hardaddr length = 6 直接数组
     * @return mac 字符串形式 参数hardaddr = null or length != 6 则返回null
     */
    public String hardaddrBytesToHexString(byte[] hardaddr) {
        if (hardaddr == null || hardaddr.length != 6) {
            return null;
        }
        char[] adr = new char[17];

        for (int i = 0; i < 5; i++) {
            adr[i * 3] = hexUpperChar(hardaddr[i]);
            adr[i * 3 + 1] = hexLowerChar(hardaddr[i]);
            adr[i * 3 + 2] = ':';
        }
        adr[15] = hexUpperChar(hardaddr[5]);
        adr[16] = hexLowerChar(hardaddr[5]);

        return new String(adr);
    }
}
