#!/usr/bin/ruby

def analyze_log(filename)
=begin
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
=end
    f = File.open(filename, 'r')
    puts "reading..."
    f.each_line do |line|
        #MAIN LOOP. ANALYZE THE LOG HERE.
        #puts line
    end
    puts "done reading"
    f.close
end

def live_capture()
    puts ("TODO :D")
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

