package com.parcom.security_client;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ChecksumTest {



    private static final long ID = 12345L;

    @Test
    public void createChecksum() {
        System.out.println(Checksum.createChecksum(ID));
    }

    @Test
    public void createChecksumNull() {
        Assertions.assertThrows(RuntimeException.class,() ->  Checksum.createChecksum(null));
    }



    @Test
    public void validateCheckSum() {
        Checksum.validateCheckSum(Checksum.createChecksum(ID),ID);

    }


    @Test
    public void validateCheckSumWrong() {
        Assertions.assertThrows(RuntimeException.class,() ->  Checksum.validateCheckSum(Checksum.createChecksum(ID),123L));
    }

    @Test
    public void validateCheckSumNull() {
        Assertions.assertThrows(RuntimeException.class,() ->   Checksum.validateCheckSum(Checksum.createChecksum(ID),null)); }


}