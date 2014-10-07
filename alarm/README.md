**Eric Bailey  
Due 7 Oct 2014  
COMP116 HW2**

---

**What has been implemented**   
Everything has been implemented to the best of my knowledge.

**Collaborators/people I've discussed it with**   
I very briefly discussed this problem with Sam Garfield.

**Hours taken**   
Somewhere around 6-10

**Are the heuristics used in this assignment to determine incidents "even that good"?**  
In my opinion, some of the heuristics used are useful (nmap scans, shellcode). 
However, I feel like alerting for each 4\*\* HTTP error is unnecessary
and a little spammy, especially for the web log. However, a number of them are actually people trying to hack into
the system, but that can be detected in other ways (ex. trying to post to wp-login.php).
Also, there are definitely more to be added to the heuristics to be considered complete.

**If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?**  
* Repeated failed requests from the same IP -- indicative of scanning/someone looking for vulns programmatically
    * Amount of time in between requests
* /netcat/i
* People trying to execute javascript
* People trying to access my files ("ls Desktop")


---

![sheep](sheep.png)
