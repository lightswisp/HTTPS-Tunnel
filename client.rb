#!/usr/bin/ruby

require "socket"
require "thread"
require "openssl"
require "colorize"

PROXY_PORT  = 8080
SERVER_HOST = "167.99.236.107"
SERVER_PORT = 443
SNI_HOST 	= "example.com" # SNI SPOOFING
TTL		 	= 10 # 10 SEC
MAX_BUFFER  = 1024 * 640 # 640KB

def connect(host, port)
	begin
		socket = TCPSocket.new(host, port)   
		return nil if !socket
		sslContext = OpenSSL::SSL::SSLContext.new
		sslContext.min_version = OpenSSL::SSL::TLS1_3_VERSION
		ssl = OpenSSL::SSL::SSLSocket.new(socket, sslContext)
		ssl.hostname = SNI_HOST
		ssl.sync_close = true
		ssl.connect 
	rescue
		puts "TLS Tunnel Server seems to be down".red
		return nil
	end
	return ssl
end

def is_alive?(ssl, request_host, request_port)
	ssl.puts("#{request_host}:#{request_port}")
	begin
	  response = ssl.readpartial(MAX_BUFFER) 
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
		request = connection.recv(MAX_BUFFER)
		Thread.exit if request.size < 1 || request.empty? || request.nil?
		request_head = request.split("\r\n")
		request_method = request_head.first.split(" ")[0] # CONNECT, GET, POST

		if request_method =~ /CONNECT/
			ssl = connect(SERVER_HOST, SERVER_PORT)
			Thread.exit if !ssl
			request_host, request_port = request_head.first.split(" ")[1].split(":")
			if header = is_alive?(ssl, request_host, request_port)
				puts "[CONNECT] #{request_host}:#{request_port}".green
				connection.puts(header)
			else
				puts "[CONNECT] #{request_host}:#{request_port} is unavailable!".red
				ssl.close
				connection.close
				Thread.exit
			end
			

			begin

			     loop do
                        fds = IO.select([connection, ssl], nil, nil, TTL)
                        if fds[0].member?(connection)
                                buf = connection.readpartial(MAX_BUFFER)
                                ssl.print(buf)
                        elsif fds[0].member?(ssl)
                                buf = ssl.readpartial(MAX_BUFFER)
                                connection.print(buf)
                        end

                end

			rescue
				puts "Closing connection with #{request_host}:#{request_port}".red
				ssl.close if ssl
				connection.close if connection
				Thread.exit
			end

		else
			# GET, POST, PUT, DELETE, PATCH, ETC
			
		end
			
	}
end
