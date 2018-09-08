
public class NetworkRule {

	 protected String direction;
     protected String protocol;
     protected int port;
     protected long ipAddress;

     /**
      * constructor for building rules
      * @param direction
      * @param protocol
      * @param port
      * @param ipAddress
      */
     public NetworkRule(String direction, String protocol, String port, String ipAddress) {
         this.direction = direction;
         this.protocol = protocol;
         this.port = Integer.parseInt(port);
         this.ipAddress = Long.parseLong(ipAddress.replaceAll("\\.", "")); 
     }

     public NetworkRule(String direction, String protocol, String port, long ipAddress) {
         this.direction = direction;
         this.protocol = protocol;
         this.port = Integer.parseInt(port);
         this.ipAddress = ipAddress;
     }

     public NetworkRule(String direction, String protocol, int port, long ipAddress) {
         this.direction = direction;
         this.protocol = protocol;
         this.port = port;
         this.ipAddress = ipAddress;
     }

     public NetworkRule(String direction, String protocol, int port, String ipAddress) {
         this.direction = direction;
         this.protocol = protocol;
         this.port = port;
         this.ipAddress = Long.parseLong(ipAddress.replaceAll("\\.", "")); //convert string ipAddress with periods to just a number
     }
     
     /**
      * This is overwritten in order to state that 2 network rule are similar when direction, 
      * protocol, port and IP address are same.
      */
     @Override
     public boolean equals(Object o) {
         if (this == o) return true;
         if (!(o instanceof NetworkRule)) return false;
         NetworkRule networkRule = (NetworkRule) o;
         return  direction.equalsIgnoreCase(networkRule.direction) && protocol.equalsIgnoreCase(networkRule.protocol)
        		 && port == networkRule.port && ipAddress == networkRule.ipAddress;
     }

     @Override
     public String toString() {
         return this.direction +  ", " + this.protocol + ", " + Integer.toString(this.port) + ", " + Long.toString(this.ipAddress);
     }


     public int hashCode() {
         long hash =  31 * (this.ipAddress + this.port + this.direction.hashCode() + this.protocol.hashCode()); //get unique key from all the components
         return Long.valueOf(hash).hashCode();
     }

 }

