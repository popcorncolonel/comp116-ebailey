#!/usr/bin/ruby

$incident = 1
def live_capture()
    def alert(attack, ip_addr, protocol, payload)
        payload = Base64.encode64(payload)
        if attack == 'Credit card' then
            puts '%d. ALERT: %s leaked in the clear from %s (%s) (%s)!' %[$incident, attack, ip_addr, protocol, payload]
        else
            puts '%d. ALERT: %s is detected from %s (%s) (%s)!' %[$incident, attack, ip_addr, protocol, payload]
        end
        $incident += 1
    end

    Signal.trap('INT'){ exit 0 } #for being able to ctrl+c it. sometimes.
    require 'packetfu'

    #I couldn't test this part because, well, I didn't want to leak creditcard info in the clear.
    #Also, I couldn't open ports on Kali (tried doing gufw to open ports, didn't work on tuftswireless)
    caps = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
    caps.stream.each do |raw|
        packet = PacketFu::Packet.parse(raw)
        ip_addr = 'ERROR - not sent using IP'
        if packet.protocol.include?('IP') then
            ip_addr = packet.ip_saddr #source address
        end
        if packet.protocol.include?('TCP') then
            if (packet.tcp_flags.fin +  #if XMAS scan
                packet.tcp_flags.psh + 
                packet.tcp_flags.urg) == 3 then
                alert('Xmas scan', ip_addr, 'TCP', packet.payload)
            end
            if (packet.tcp_flags.urg +  #if NULL scan
                packet.tcp_flags.ack + 
                packet.tcp_flags.psh + 
                packet.tcp_flags.rst +
                packet.tcp_flags.syn + 
                packet.tcp_flags.fin) == 0 then
                alert('NULL scan', ip_addr, 'TCP', packet.payload)
            end
        end
        #if the packet matches a credit card regex OVER A WEBSITE (HTTP)
        if packet.protocol.include?('HTTP') then
            if packet.payload =~ /((4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4})|(5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4})|(6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4})|(3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}))/ then
                alert('Credit card', ip_addr, 'HTTP', packet.payload)
            end
        end
    end
end

def analyze_log(filename)

    def alert(attack, ip_addr, protocol, payload)
        payload = Base64.encode64(payload)
        puts '%d. ALERT: %s is detected from %s (%s) ("%s")!' %[$incident, attack, ip_addr, protocol, payload]
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
        else
            protocol = 'HTTP'
        end

        #nmap
        if line =~ /nmap/ then 
            alert('NMAP scan', ip_addr, protocol, request)
        end

        #bad status code
        if status_code.to_i >= 400 then
            if request == '' then request = '-' end
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

