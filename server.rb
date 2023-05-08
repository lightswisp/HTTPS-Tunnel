#!/usr/bin/ruby
require 'socket'
require 'openssl'
require 'colorize'
require 'timeout'

PORT = 443
SERVER_NAME = "Rubinius_1.0.16/(#{RUBY_VERSION})/(#{OpenSSL::OPENSSL_VERSION})"
CONN_OK = "HTTP/1.1 200 Established\r\nDate: #{Time.now}\r\nServer: #{SERVER_NAME}\r\n\r\n"
CONN_FAIL = "HTTP/1.1 502 Bad Gateway\r\nDate: #{Time.now}\r\nServer: #{SERVER_NAME}\r\n\r\n"
TTL = 10 # 10 seconds io select timeout
TCP_CONN_TIME_ABORT = 10 # 10 seconds timeout to abort the connection if tls connection is still in the PINIT state. This feature was made to drop all tcp connections that didn't start the tls negotiation process 

# SSL Configuration
SSL = {
         :SSLClientCA=>nil,
         :SSLExtraChainCert=>nil,                         
         :SSLCACertificateFile=>nil,                      
         :SSLCACertificatePath=>nil,                      
         :SSLCertificateStore=>nil,                       
         :SSLTmpDhCallback=>nil,                          
         :SSLVerifyClient=>OpenSSL::SSL::VERIFY_PEER,                             
         :SSLVerifyDepth=>5,                            
         :SSLVerifyCallback=>nil,
         :SSLTimeout=>2,                                
         :SSLOptions=>nil,                                
         :SSLCiphers=>nil,                                
         :SSLStartImmediately=>true,                      
         :SSLCertName=>nil,   
         :SSLVer=>OpenSSL::SSL::TLS1_3_VERSION
}

socket = TCPServer.new(PORT)
puts "Listening on #{PORT}"

sslContext 								= OpenSSL::SSL::SSLContext.new()
sslContext.cert                         = OpenSSL::X509::Certificate.new(File.open("certificate.crt"))
sslContext.key                          = OpenSSL::PKey::RSA.new(File.open("private.key"))
sslContext.verify_mode                  = SSL[:SSLVerifyClient]
sslContext.verify_depth                 = SSL[:SSLVerifyDepth]
sslContext.timeout                      = SSL[:SSLTimeout]
sslContext.min_version                  = SSL[:SSLVer] # *IMPORTANT* TLS_1.3 


def handle_client(connection)
        puts "[*] New connection #{connection.peeraddr[-1]}:#{connection.peeraddr[1]}"
        address = connection.gets
        if address.match?(/GET/) # if it's not the address but the actual request from the client's browser
	        response = "HTTP/1.1 200 OK\r\nServer: #{SERVER_NAME}\r\nContent-Type: text/html\r\n\r\n#{File.read('index.html')}"
	        connection.puts(response)
	        connection.close
	        puts "[LOGS] Webpage is shown, closing the connection...".green
	        Thread.exit
        end
        begin
	        endpoint_host = address.split(":")[0]
	        endpoint_port = address.split(":")[1].to_i
        rescue
	        puts "[WARNING] Client doesn't know how to communicate with us!"
	        connection.close if connection
	        Thread.exit
        end

        puts "#{endpoint_host}:#{endpoint_port}".green
        endpoint_connection = TCPSocket.new(endpoint_host, endpoint_port)
        endpoint_connection.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true) 

        if endpoint_connection
          connection.puts(CONN_OK)
        else
          connection.puts(CONN_FAIL)
          connection.close
          Thread.exit
        end

		begin
			loop do
				fds = IO.select([connection, endpoint_connection], nil, nil, TTL)
				if fds[0].member?(connection)
				  buf = connection.readpartial(1024 * 640)
				  endpoint_connection.print(buf)
				elsif fds[0].member?(endpoint_connection)
				  buf = endpoint_connection.readpartial(1024*640)
				  connection.print(buf)
				end
			end
		rescue
			puts "[*] Closing connection with #{endpoint_host}:#{endpoint_port}".red
			endpoint_connection.close() if endpoint_connection
			connection.close() if connection
			Thread.exit
		end

end

# The main loop

loop do
	Thread.new(socket.accept) do |connection|

		begin
			tls = OpenSSL::SSL::SSLSocket.new(connection, sslContext)
			state = tls.state
			Timeout.timeout(10) do
			  tls_connection  = tls.accept
			  handle_client(tls_connection) if tls_connection
			end
		rescue Timeout::Error
			if connection && state == "PINIT"
			  connection.close                
			end
		rescue => e
			puts "[ERROR] #{e}".red
			connection.close if connection
		end

	end
end
