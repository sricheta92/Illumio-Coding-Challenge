package com.illumio.dev;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.HashSet;
import java.util.Set;

/**
 * 
 * @author Sricheta's computer
 *
 */
public class Firewall {

	static Set<NetworkRule> rules = new HashSet<NetworkRule>();

	public static void main(String[] args) {

		Firewall f = new Firewall("networkrules.csv");
		boolean test1 = f.acceptPacket("outbound", "tcp", 20000, "192.168.10.11");
		boolean test2 = f.acceptPacket("inbound", "tcp",80,"192.168.1.2");
		boolean test3 = f.acceptPacket("inbound", "tcp",80,"192.168.1.322");
		boolean test4 = f.acceptPacket("inbound", "udp",43,"12.53.6.25");
		boolean test5 = f.acceptPacket("inbound", "tcp",673,"123.45.56.83");
		System.out.println(test1);
		System.out.println(test2);
		System.out.println(test3);
		System.out.println(test4);
		System.out.println(test5);

	}

	public Firewall(String filename){

		try(BufferedReader br = new BufferedReader(new FileReader(filename))) {

			String line;
			while((line = br.readLine()) != null) {

				String [] rule = line.split(",");

				/* When rule has range of ports*/
				if (rule[2].contains("-")) { 
					String [] portRanges = rule[2].split("-");
					int portMin = Integer.parseInt(portRanges[0]);
					int portMax = Integer.parseInt(portRanges[1]);
					int portRange = portMax - portMin;

					/* When rule has range in octet of ip address */
					if (rule[3].contains("-")) {
						String [] ipAddressRanges = rule[3].split("-");
						long ipAddressMin = Long.parseLong(ipAddressRanges[0].replaceAll("\\.", ""));
						long ipAddressMax = Long.parseLong(ipAddressRanges[1].replaceAll("\\.", ""));
						long ipRange = ipAddressMax - ipAddressMin;

						//iterate through all possible ports and ips and add them to set
						for (int i = 0; i <= portRange; i++) {
							for (int j = 0; j <= ipRange; j++) {
								NetworkRule currRule = new NetworkRule(rule[0], rule[1], portMin + i, ipAddressMin + j);
								rules.add(currRule);
							}
						}

						//iterate through all possible ports and ips and add them to set
						for (int i = 0; i <= portRange; i++) {
							for (int j = 0; j <= ipRange; j++) {
								NetworkRule currRule = new NetworkRule(rule[0], rule[1], portMin + i, ipAddressMin + j);
								rules.add(currRule);
							}
						}
					}else{

						//iterate through all possible ports add them to mssetap
						for (int i = 0; i <= portRange; i++) {
							NetworkRule currRule = new NetworkRule(rule[0],rule[1], portMin + i, rule[3]);
							rules.add(currRule);
						}
					}
				}  

				else /* When rule has no range of ports*/

				{ 
					/* When rule has  range of ip address*/
					if (rule[3].contains("-")) {
						String [] ipAddressRanges = rule[3].split("-");
						long ipAddressMin = Long.parseLong(ipAddressRanges[0].replaceAll("\\.", ""));
						long ipAddressMax = Long.parseLong(ipAddressRanges[1].replaceAll("\\.", ""));
						long ipRange = ipAddressMax - ipAddressMin;

						//iterate through all possible ips add them to map
						for (int i = 0; i <= ipRange; i++) {
							NetworkRule currRule = new NetworkRule(rule[0],rule[1],rule[2], ipAddressMin + i);
							rules.add(currRule);
						}
					}
					else 
						/* When rule has  no range of ip address*/
					{ 
						NetworkRule currRule = new NetworkRule(rule[0],rule[1],rule[2],rule[3]);
						rules.add(currRule);
					}

				}

			}
		}
		catch (FileNotFoundException e) {
			System.out.println("Cannot find file "+ filename );
		}
		catch(Exception e) {
			System.out.println("Exeption occured " + e.getMessage());
		}
	}

	/**
	 * This function decides whether to accept the packet or not by looking up to the rule Set.
	 * @param direction
	 * @param protocol
	 * @param port
	 * @param ipAddress
	 * @return
	 */
	public boolean acceptPacket(String direction, String protocol, int port, String ipAddress) {
		NetworkRule rule = new NetworkRule(direction, protocol, port, ipAddress);
		if (rules.contains(rule)) {
			return true;
		}
		else {
			return false;
		}

	}

}
