Phantom Presence v2.0
Advanced Behavioral Deception & System Activity Simulation Engine for Red Teaming

Phantom Presence is a Python-based deception system that generates realistic system activity, honey artifacts, and simulated user behavior. It creates operational noise to confuse threat actors, test detection pipelines, or enhance red‑team labs with believable behavioral patterns.



##  Features

- Realistic fake system activity generation  
- Authentication events (logins, logouts, failures)  
- File system modifications & honey file creation  
- Fake user interaction patterns  
- Suspicious beacon-like network traffic  
- Process start/end simulation  
- DNS queries & connection noise  
- Centralized logging to `phantom_presence.log`  
- Modular event engine for expansion  


## Example Output
[16:52:13] Generated: authentication.login
[16:52:19] Generated: filesystem.modify
[16:53:37] Generated: suspicious.beacon_traffic
[16:54:25] Generated: authentication.login
[16:55:35] Generated: network.dns_query
[16:56:45] Simulation stopped by user
