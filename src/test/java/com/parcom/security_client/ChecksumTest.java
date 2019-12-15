package com.parcom.security_client;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class ChecksumTest {



    private static final long ID = 12345L;

    @Test
    public void createChecksum() {
        System.out.println(Checksum.createChecksum(ID));
    }

    @Test(expected = RuntimeException.class)
    public void createChecksumNull() {
        Checksum.createChecksum(null);
    }



    @Test
    public void validateCheckSum() {
        Checksum.validateCheckSum(Checksum.createChecksum(ID),ID);

    }


    @Test(expected = RuntimeException.class)
    public void validateCheckSumWrong() {
        Checksum.validateCheckSum(Checksum.createChecksum(ID),123L);

    }

    @Test(expected = RuntimeException.class)
    public void validateCheckSumNull() {
        Checksum.validateCheckSum(Checksum.createChecksum(ID),null);

    }


}