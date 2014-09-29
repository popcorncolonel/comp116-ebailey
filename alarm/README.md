**Eric Bailey  
Due 7 Oct 2014  
COMP116 HW2**

---

**What has been implemented**  
Nothing yet

**Collaborators/people I've discussed it with**  
No one so far

**Hours taken**  
0 so far

**Are the heuristics used in this assignment to determine incidents "even that good"?**


**If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?**


#TODO#
* write log analyzer
* write live alarm
* remove notes
* Ask this question: What do we do if there is more than one thing wrong with the log? (ex. shellcode and 4\*\* error) Do we print each error? Just the first one we hit?
* remove sheep?

---

**MUST DETECT**
* NMAP scan (of any variety)
* HTTP errors, anything that has an HTTP status code in the 400-range
* Shellcode. 

**NOTES** (about access.log)
* user-agent from nmap

![sheep](sheep.png)
