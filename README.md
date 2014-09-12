Eric Bailey
Due 16 Sept 2014
COMP116 HW1

###set1.pcap###

####1. How many packets are there in this set?
1503

####2. What protocol was used to transfer files from PC to server?
FTP (port 21)

####3. Briefly describe why the protocol used to transfer the files is insecure?
The plaintext and files are unencrypted. For example, in packets 118 and 192, anyone listening to the network stream (which is very easy to do), can see the username and password in the clear.

####4. What is the secure alternative to the protocol used to transfer files?
OpenSSH (Open source Secure Shell) or SFTP (SSH File Transfer Protocol).

####5. What is the IP address of the server?
10.245.145.124

####6. What was the username and password used to access the server?
user: ihackpineapples  
pass: rockyou1

####7. How many files were transferred from PC to server?
Four

####8. What are the names of the files transferred from PC to server?
BjN-O1hCAAAZbiq.jpg  
BvgT9p2IQAEEoHu.jpg  
BvzjaN-IQAA3XG7.jpg  
smash.txt

####9. Extract all the files that were transferred from PC to server. These files must be part of your submission!
![one](BjN-O1hCAAAZbiq.jpg)
![two](BvgT9p2IQAEEoHu.jpg)
![three](BvzjaN-IQAA3XG7.jpg)

###set2.pcap###

####10. How many packets are there in this set?

####11. How many plaintext username-password pairs are there in this packet set?

####12. Briefly describe how you found the username-password pairs.

####13. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.

####14. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted?

####15. How did you verify the successful username-password pairs?

####16. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?

