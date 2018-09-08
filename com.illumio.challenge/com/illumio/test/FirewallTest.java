package com.illumio.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.illumio.dev.Firewall;

public class FirewallTest {
	
    static Firewall f = null;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		f = new Firewall("networkrules.csv");
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testAcceptPacket() {
		boolean acceptPacket = f.acceptPacket("outbound", "tcp", 20000, "192.168.10.11");
		assertEquals("This will be true", true, acceptPacket);
	}

}
