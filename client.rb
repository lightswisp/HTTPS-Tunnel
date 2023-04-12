#!/usr/bin/ruby

require "socket"
require "thread"
require "openssl"
require "colorize"

PROXY_PORT = 8080
SERVER_HOST = "167.99.236.107"
SERVER_PORT = 443
SNI_HOST = "example.com" # SNI SPOOFING
TTL		 = 60 # 60 seconds

def connect(host, port)
	socket = TCPSocket.new(host, port)   
	return nil if !socket
	ssl = OpenSSL::SSL::SSLSocket.new(socket)
	ssl.io.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
    ssl.io.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, true)
	ssl.hostname = SNI_HOST
	ssl.sync_close = true
	ssl.connect 
	return ssl
end

def is_alive?(ssl, request_host, request_port)
	ssl.puts("#{request_host}:#{request_port}")
	begin
	  response = ssl.readpartial(1024 * 640) 
	rescue
		return nil
	end
	return response
end


proxy = TCPServer.new(PROXY_PORT)
puts "Listening on #{PROXY_PORT}"

loop do
	connection = proxy.accept
	Thread.new {
		request = connection.recv(1024 * 640)
		Thread.exit if request.size < 1 || request.empty? || request.nil?
		request_head = request.split("\r\n")
		request_method = request_head.first.split(" ")[0] # CONNECT, GET, POST

		if request_method =~ /CONNECT/
			ssl = connect(SERVER_HOST, SERVER_PORT)
			return if !ssl
			request_host, request_port = request_head.first.split(" ")[1].split(":")
			if header = is_alive?(ssl, request_host, request_port)
				puts "[CONNECT] #{request_host}:#{request_port}".green
				connection.puts(header)
			else
				puts "[CONNECT] #{request_host}:#{request_port} is unavailable!".red
				ssl.close
				connection.close
			end
			

			begin

			     loop do
                        fds = IO.select([connection, ssl], nil, nil, TTL)
                        if fds[0].member?(connection)
                                buf = connection.readpartial(1024 * 640)
                                ssl.print(buf)
                        elsif fds[0].member?(ssl)
                                buf = ssl.readpartial(1024*640)
                                connection.print(buf)
                        end

                end

			rescue
				puts "Closing connection with #{request_host}:#{request_port}".red
				ssl.close if ssl
				connection.close if connection
				Thread.exit
			end

	
		end
			
	}
end



# Thread.new {
  # begin
    # while lineIn = ssl.gets
      # lineIn = lineIn.chomp
      # $stdout.puts lineIn
    # end
  # rescue
    # $stderr.puts "Error in input loop: " + $!
  # end
# }
# 
# while (lineOut = $stdin.gets)
  # lineOut = lineOut.chomp
  # ssl.puts lineOut
# end
