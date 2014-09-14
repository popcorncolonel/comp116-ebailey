**Eric Bailey  
Due 16 Sept 2014  
COMP116 HW1**

---

####set1.pcap

**1. How many packets are there in this set?**  
1503

**2. What protocol was used to transfer files from PC to server?**  
FTP (port 21)

**3. Briefly describe why the protocol used to transfer the files is insecure?**  
The plaintext and files are unencrypted. For example, in packets 118 and 192, anyone listening to the network stream (which is very easy to do), can see the username and password in the clear. Same goes for the files transferred to the server.

**4. What is the secure alternative to the protocol used to transfer files?**  
OpenSSH (Open source Secure Shell) or SFTP (SSH File Transfer Protocol).

**5. What is the IP address of the server?**  
10.245.145.124

**6. What was the username and password used to access the server?**  
user: ihackpineapples  
pass: rockyou1

**7. How many files were transferred from PC to server?**  
Four

**8. What are the names of the files transferred from PC to server?**  
BjN-O1hCAAAZbiq.jpg  
BvgT9p2IQAEEoHu.jpg  
BvzjaN-IQAA3XG7.jpg  
smash.txt

**9. Extract all the files that were transferred from PC to server. These files must be part of your submission!**  
![one](BjN-O1hCAAAZbiq.jpg)
![two](BvgT9p2IQAEEoHu.jpg)
![three](BvzjaN-IQAA3XG7.jpg)
[smash.txt](smash.txt)

####set2.pcap

**10. How many packets are there in this set?**  
77882

**11. How many plaintext username-password pairs are there in this packet set?**  
I was able to find 9 unique pairs ([chris@digitalinterlude.com](mailto:chris@digitalinterlude.com) was used to log in successfully twice).

**12. Briefly describe how you found the username-password pairs.**  
*Most useful tools*: 
* Wireshark (filtering by specific insecure protocols and ports led to the most success)
    * tcp contains "(pass|password|PASS|Password|login|user|username|success)"
* tshark (told me where to look. "tshark -r set2.pcap -q -z io,phs")
* ngrep -q -I set2.pcap | grep \[-i] (pass|password|PASS|Password|login|user|username|success)

I used these tools to search for "password", "login", things of that natures in the pcap file. Lots of following TCP streams as well.

**13. For each of the plaintext username-password pair that you found, identify the protocol used,  Server IP, the corresponding domain name (e.g., google.com), and port number.**  

=POP=  
**Protocol**: POP; **Server IP**: 75.126.75.131;**Domain**: mail.si-sv3231.com; **Port**:83  
**Username**: "chris@digitalinterlude.com" **Password**: "Volrathw69"; 

**Protocol**: POP; **Server IP**: 75.126.75.131;**Domain**: aece765e-be1e-4e0d-a4ab-e4cb003228d7@mail.si-sv3231.com; **Port**:83
**Username**: "chris@digitalinterlude.com" **Password**: "Volrathw69"; 

=TELNET=  
**Protocol**: TELNET;  **Server IP**: 200.60.17.1; **Domain**: (local cisco router); **Port**: 23  
**Username**: "cisco" **Password**: "185 august23"  

**Protocol**: TELNET;  **Server IP**: 200.60.17.1; **Domain**: (local cisco router); **Port**: 23  
**Username**: "cisco" **Password**: "185 anthony7"  

**Protocol**: TELNET;  **Server IP**: 200.60.17.1; **Domain**: (local cisco router); **Port**: 23  
**Username**: "cisco" **Password**: "185 allahu"  

**Protocol**: TELNET;  **Server IP**: 200.60.17.1; **Domain**: (local cisco router); **Port**: 23  
**Username**: "cisco" **Password**: "185 alannah"  

**Protocol**: TELNET;  **Server IP**: 200.60.17.1; **Domain**: (local cisco router); **Port**: 23  
**Username**: "cisco" **Password**: "185 BASKETBALL"  

**Protocol**: TELNET;  **Server IP**: 200.60.17.1; **Domain**: (local cisco router); **Port**: 23  
**Username**: "cisco" **Password**: "185 12345d"  

**Protocol**: TELNET;  **Server IP**: 200.60.17.1; **Domain**: (local cisco router); **Port**: 23  
**Username**: "cisco" **Password**: "185 122333"  

**Protocol**: TELNET;  **Server IP**: 200.60.17.1; **Domain**: (local cisco router); **Port**: 23  
**Username**: "cisco" **Password**: "184 yomama1"  

**14. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted?**  
Regarding the _unique_ (UN,PW) pairs I found, the only valid pair is (chris@digitalinterlude.com, Volrathw69). However, it was used to log in two different times (TCP streams 144 and 627).

**15. How did you verify the successful username-password pairs?**  
For POP, the server responded with "+OK Password ok" for valid pairs rather than "% Login invalid" like TELNET gives. I looked for similar human-readable clues (such as "Login successful," "Access granted", etc.)

**16. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?**  

* Use secure, encrypted protocols (like SSH or HTTPS) rather than the alternative (TELNET, POP, FTP, etc.) when dealing with sensitive information such as usernames and passwords.

* Always use trusted Internet sources (not free public WiFi's) when logging in.

* Take COMP116 via Tufts University

