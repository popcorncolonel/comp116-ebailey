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
    Signal.trap('INT'){ exit 0 } #for being able to ctrl+c it
    require 'packetfu'

    stream = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
    i = 1
    while true
        sleep 1
        stream.save
        stream.stream.each do |p|
            packet = ::PacketFu::Packet.parse(p)
            #if NULL scan then end
            #if Xmas scan then end
            #if Credit Card then end #
            #CREDIT CARD REGEX: /(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})/
            #- http://stackoverflow.com/questions/9315647/regex-credit-card-number-tests
            puts packet.peek
            puts "==============================================================================="
            puts packet.payload
            puts packet.protocol
            puts i
            i += 1
            puts 
        end
        #puts stream.array.length
        #puts stream.array[stream.array.length-1].to_s
    end
end

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

def analyze_log(filename)
    $incident = 1

    def alert(attack, ip_addr, protocol, payload)
        puts '%d. ALERT: %s is detected from %s (%s) ("%s")!' %[$incident, attack, ip_addr, protocol, payload]
        #if attack == 'NMAP scan' then
        #    puts '%d. ALERT: %s is detected from %s (%s) ("%s")!' %[$incident, attack, ip_addr, protocol, payload]
        #end
        $incident += 1
    end

    def has_shellcode?(str)
        #shellcodes appear to be of the form /(\\x[0-9a-f]{2}.{0,1}){3,}/i
        #AND at the beginning of strings!
        return (str =~ /(\\x[0-9a-f]{2}.{0,1}){3,}/i) == 0 #aka if it's at the beginning of the line
    end
    
    def analyze_log_line(line)
        error_statement = nil

        protocol = nil
        ip_addr = line.split(' ')[0]
        request = line.split('"')[1]
        status_code = line.split('"')[2].split(' ')[0]
        user_agent = line.split('"')[5]


        if request != '' then #some lines are like this with no payloads o.O with 400 errors
            #shellcode
            if has_shellcode?(request) then
                protocol = 'HTTP'
                alert('Shellcode', ip_addr, protocol, request)
            end

            if protocol == nil then
                protocol = request.split(' ')[-1].split('/')[0]
            end
            if protocol != 'HTTP' and protocol != 'RTSP' and protocol != 'HTTPS' then
                protocol = 'HTTP'
            end
        end

        #nmap
        if line =~ /nmap/ then 
            alert('NMAP scan', ip_addr, protocol, request)
        end

        #bad status code
        if status_code.to_i >= 400 then
            alert('HTTP error', ip_addr, protocol, request)
        end

    end

    f = File.open(filename, 'r')
    f.each_line do |line|
        line = analyze_log_line(line)
    end
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

