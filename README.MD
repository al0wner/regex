To apply the changes:

    1. Remove the build directory `rm -rf ./build` from `$SDE`.
    
    2. Merge the open-p4studio directory with `$SDE`.
    
    3. Run the install script afterward, `./p4studio/p4studio profile apply ./p4studio/profiles/testing.yaml`. 
    

To run two different Tofino simulations at a time:

	1. Run the DFA device without default settings: 
	
		`./run_tofino_model.sh -p dfa --arch tofino`  
		
		`./run_switchd.sh -p dfa --arch tofino`
		
	2. Run the halfsiphash device with additional parameters: 
	
		`./run_tofino_model.sh -p halfsiphash --arch tofino -t 8011 -P 8010`
		
		`./run_switchd.sh -p halfsiphash --arch tofino --tcp-port-base 8011 --pd-api-port 9091 --switchd-listen-port 9998 --bfrt-grpc-port 50053`


To listen to a veth@:

	`sudo tcpdump -i veth@ -nn -X`

To send a packet that must be hashed to veth@:

```
sudo python3 -c "
from scapy.all import Ether, IP, sendp, Raw

sip_bytes = (1).to_bytes(4,'big') + (2).to_bytes(4,'big') + (3).to_bytes(4,'big') + (4).to_bytes(4,'big') + (5).to_bytes(4,'big')
val_bytes = (0).to_bytes(1,'big') + (1).to_bytes(1,'big') + (1).to_bytes(1,'big') + (0).to_bytes(4,'big') + (0).to_bytes(4,'big') + (0).to_bytes(4,'big') + (0).to_bytes(1,'big')
inner_bytes = sip_bytes + val_bytes

pkt = Ether(dst='00:11:22:33:44:55', src='11:33:55:77:99:00')/IP(dst='10.0.2.2', proto=0xf0)/Raw(inner_bytes)

sendp(pkt, iface='veth@')
"
```

Replace @ with the number.  

For example, listening to port 65 and sending to 65 should dump two packets on screen, one that goes in through 65 and one that comes out from 65 after hashing.
