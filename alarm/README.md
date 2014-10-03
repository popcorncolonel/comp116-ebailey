**Eric Bailey  
Due 7 Oct 2014  
COMP116 HW2**

---

**What has been implemented**  
So far, the log reader has been implemented to the best of my knowledge.

**Collaborators/people I've discussed it with**  
I have not discussed this problem.

**Hours taken**  
2

**Are the heuristics used in this assignment to determine incidents "even that good"?**
Some of the heuristics used are useful (nmap scans, shellcode). 
Especially for the web log, however, I feel like the 4\*\* HTTP errors are unnecessary
and a little spammy. However, a number of them are actually people trying to hack into
the system, but that can be detected in other ways (ex. trying to post to wp-login.php).
Also, there is definitely more to be added to the heuristics to be considered complete.

**If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?**
* Repeated failed requests from the same IP -- indicative of scanning/someone looking for vulns programmatically
    * Amount of time in between requests
* People trying to execute javascript
* People trying to access my files ("ls Desktop")
* Netcat


#TODO#
* write live alarm
    * How do I get the flags of the live packets?
* Remove (some) notes
* Remove sheep?

---

![sheep](sheep.png)
