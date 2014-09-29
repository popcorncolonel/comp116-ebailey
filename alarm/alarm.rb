#!/usr/bin/ruby

def live_capture()
=begin
    ***MUST DETECT***
NULL scan
Xmas scan
Credit card number leaked in the clear via website

***IN THE FORM***
#{incident_number}. ALERT: #{attack} is detected from #{source IP address} (#{protocol}) (#{payload})!

OR

#{incident_number}. ALERT: Credit card leaked in the clear from #{source IP address} (#{protocol}) (#{payload})!

=end
    puts ("TODO :D")
end

def analyze_log(filename)
=begin
    **NOTES** (about access.log)
    * if the user agent is from nmap then... yeah... cmon...

    ***MUST DETECT***
NMAP scan (of any variety)
HTTP errors, anything that has an HTTP status code in the 400-range
Shellcode. For some background reading on shellcode and what it is, read https://morgawr.github.io/hacking/2014/03/29/shellcode-to-reverse-bind-with-netcat/

***IN THE FORM***
#{incident_number}. ALERT: #{attack} is detected from #{source IP address} (#{protocol}) (#{payload})!

***LINE FORMAT***
73.38.0.142 - - [11/Sep/2014:23:49:48 +0200] "HEAD /import HTTP/1.1" 404 0 "-" "Mozilla/5.0"
*TOKENS*
IP - - [date:time +tz] "request" statuscode ? ? "user-agent"

=end

    #CONTRACT: takes in a line of a server log. 
    # Returns the nil if the does not trigger one of the 3 alerts
    # Returns the properly formatted alert message (starting after "ALERT: ")
    def read_incident(line)
        to_return = nil
            #tokenize based on spaces " then by spaces
        #if it's an nmap scan (how 2 detect?) (just see if line is coming from nmap? is there a way it's coming from an nmap scan but not from user-agent nmap?)
        #if it has a 4** http response (easy. regex.)
        puts line
        ip_addr = line.split(' ')[0]
        request = line.split('"')[1]
        status_code = line.split('"')[2].split(' ')[0]
        user_agent = line.split('"')[5]
        #puts ip_addr
        #puts request
        #puts status_code
        puts user_agent
        #if it's shellcode (read thing)
        #shellcodes appear to be of the form (\\x[0-9a-f]{2}){3,} and paired with a 400 error code (NOT TRUE IF IT WORKED? OR IS IT?) but 400 error code not 100% required from what i can tell.
        return to_return
    end

    f = File.open(filename, 'r')
    puts "reading..."
    incident = 1
    f.each_line do |line|
        line = read_incident(line)
        if line != nil
            puts incident.to_s + '. ALERT: ' + line
            incident += 1
        end
    end
    puts "done reading"
    f.close
end


flag = ARGV[0]
filename = ARGV[1]
if flag == nil
    live_capture()
elsif flag == '-r' and filename != nil
    analyze_log(filename)
else
    puts "Usage: ruby alarm.rb [-r <web_server_log>]"
end

