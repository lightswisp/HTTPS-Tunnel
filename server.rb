#!/usr/bin/ruby
require 'socket'
require 'openssl'
require 'colorize'

PORT = 443
CONN_OK = "HTTP/1.1 200 Established\r\nDate: #{Time.now}\r\nServer: Apache 2.0.1\r\n\r\n"
CONN_FAIL = "HTTP/1.1 502 Bad Gateway\r\nDate: #{Time.now}\r\nServer: Apache 2.0.1\r\n\r\n"

socket = TCPServer.new(PORT)
sslContext = OpenSSL::SSL::SSLContext.new
sslContext.cert = OpenSSL::X509::Certificate.new(File.open("certificate.crt"))
sslContext.key = OpenSSL::PKey::RSA.new(File.open("private.key"))
sslServer = OpenSSL::SSL::SSLServer.new(socket, sslContext)
puts "Listening on #{PORT}"

def handle_client(connection)
        puts "new connection #{connection}"
        address = connection.gets
        endpoint_host = address.split(":")[0]
        endpoint_port = address.split(":")[1].to_i
        puts "#{endpoint_host}:#{endpoint_port}"
        endpoint_connection = TCPSocket.new(endpoint_host, endpoint_port)
        endpoint_connection.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true) 
        if endpoint_connection
                connection.puts(CONN_OK)
        else
                connection.puts(CONN_FAIL)
                connection.close
                return
        end

        begin
                loop do
                        fds = IO.select([connection, endpoint_connection], nil, nil)
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
        end
end

loop do
        connection = sslServer.accept
        Thread.new do
                begin
            connection.io.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true) 
            connection.io.setsockopt(Socket::SOL_TCP, Socket::TCP_NODELAY, true)
                        handle_client(connection)
                rescue => e
                        puts "Critical error #{e}"
                end
        end 
end
