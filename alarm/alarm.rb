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
        attack = attack
        puts '%d. ALERT: %s is detected from %s (%s) ("%s")!' %[$incident, attack, ip_addr, protocol, payload]
        $incident += 1
    end

    def has_shellcode?(str)
        #shellcodes appear to be of the form /(\\x[0-9a-f]{2}.{0,1}){3,}/i
        #AND at the beginning of strings!
        return str =~ /(\\x[0-9a-f]{2}.{0,1}){3,}/i
    end
    
    def analyze_log_line(line)
        error_statement = nil

        ip_addr = line.split(' ')[0]
        request = line.split('"')[1]
        status_code = line.split('"')[2].split(' ')[0]
        user_agent = line.split('"')[5]

        if request != '' then #some lines are like this o.O with 400 errors
            if has_shellcode?(request) == 0 then
                alert('shellcode', ip_addr, 'HTTP', request)
                return
            end
            #alert(incident, 'HTTP error', ip_addr, protocol, payload)
            # if request is shellcode, alert
            protocol = request.split(' ')[-1].split('/')[0]
            if protocol != 'HTTP' and false then
                puts
                puts
                puts protocol
                puts line
                puts
                puts
            end
        else
            #puts status_code
        end

        #bad status code
        if status_code.to_i >= 400 then
            #alert(incident, 'HTTP error', ip_addr, protocol, payload)
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

