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
* remove sheep?

---

**NOTES** (about access.log)
* tons and tons of the same thing together (trying to login to wp hundreds of times per minute) => not good guy
    * yeah. line 12879 - hundreds of 404's per second.
    * In general: 1 IP, thousands of things per second => bad
* People whose first requests are /robots.txt are generally good?
    * stuff with \*bot/[0-9].[0-9] in the user agent are generally good (bingbot, googlebot, yandexbot)
* if the user agent is from nmap then... yeah... cmon...
* Anything with /scanner/i in the user-agent is no.
* IPs from whom the majority of requests have response 2\*\* are generally good?
* stuff coming from w3af.org... probably not good

![sheep](sheep.png)
