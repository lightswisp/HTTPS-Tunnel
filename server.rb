#!/usr/bin/ruby
require 'socket'
require 'openssl'
require 'colorize'
require 'timeout'
require 'optparse'

PUBLIC_IP = `curl -s ifconfig.me`
MAX_BUFFER = 1024 * 640 # 640KB
PORT = 443 # Don't change this, because this server imitates the real https server
SERVER_NAME = "Rubinius_1.0.16/(#{RUBY_VERSION})/(#{OpenSSL::OPENSSL_VERSION})"
CONN_OK = "HTTP/1.1 200 Established\r\nDate: #{Time.now}\r\nServer: #{SERVER_NAME}\r\n\r\n"
CONN_FAIL = "HTTP/1.1 502 Bad Gateway\r\nDate: #{Time.now}\r\nServer: #{SERVER_NAME}\r\n\r\n<h1>502 Bad Gateway</h1>"
TTL = 10 # 10 seconds io select timeout
TCP_CONN_TIME_ABORT = 10 # 10 seconds timeout to abort the connection if tls connection is still in the PINIT state. This feature was made to drop all tcp connections that didn't start the tls negotiation process
OPTIONS = {}

# SSL Configuration
SSL = {
  SSLClientCA: nil,
  SSLExtraChainCert: nil,
  SSLCACertificateFile: nil,
  SSLCACertificatePath: nil,
  SSLCertificateStore: nil,
  SSLTmpDhCallback: nil,
  SSLVerifyClient: OpenSSL::SSL::VERIFY_PEER,
  SSLVerifyDepth: 5,
  SSLVerifyCallback: nil,
  SSLTimeout: 2,
  SSLOPTIONS: nil,
  SSLCiphers: nil,
  SSLStartImmediately: true,
  SSLCertName: nil,
  SSLVer: OpenSSL::SSL::TLS1_3_VERSION
}

OptionParser.new do |opts|
  opts.banner = "TLS Tunnel Server\n\n".bold + 'Usage: ./server.rb [OPTIONS]'
  opts.on('-v', '--verbose', 'Run verbosely') do |v|
    OPTIONS[:verbose] = v
  end

  opts.on('-h', '--help', 'Prints help') do
    puts opts
    exit
  end

  opts.on('-fKEY', '--auth-keyfile=KEY',
          'TLS Tunnel Server authorization key file, example: ./server.rb --auth-keyfile auth_key.txt') do |auth_key|
    OPTIONS[:auth_key] = auth_key
  end

  opts.on('-cCERT', '--certificate=CERT',
          'SSL Certificate, example: ./server.rb --certificate certificate.crt --key private.key') do |cert|
    OPTIONS[:cert] = cert
  end
  opts.on('-kKEY', '--key=KEY',
          'Private key, example: ./server.rb --certificate certificate.crt --key private.key') do |key|
    OPTIONS[:key] = key
  end
end.parse!

if Process.uid != 0
  puts 'You must run it as root!'.red
  exit
end

if !OPTIONS[:cert] || !OPTIONS[:key] || !OPTIONS[:auth_key]
  puts "Please provide your ssl certificate, authentication key file and private key!\nExample: ./server.rb --certificate/-c certificate.crt --key/-k private.key --auth-keyfile/-f auth_key.txt".red
  exit
end

if !File.exist?(OPTIONS[:cert]) || !File.exist?(OPTIONS[:key]) || !File.exist?(OPTIONS[:auth_key])
  puts 'SSL Certificate or private key or authentication key not found! Please double check your local directory'.red
  exit
end

AUTH_KEY = File.read(OPTIONS[:auth_key]).chomp
socket = TCPServer.new(PORT)
puts "[#{Time.now}] Listening on #{PORT}".bold

sslContext = OpenSSL::SSL::SSLContext.new
sslContext.cert             = OpenSSL::X509::Certificate.new(File.open(OPTIONS[:cert]))
sslContext.key              = OpenSSL::PKey::RSA.new(File.open(OPTIONS[:key]))
sslContext.verify_mode      = SSL[:SSLVerifyClient]
sslContext.verify_depth     = SSL[:SSLVerifyDepth]
sslContext.timeout          = SSL[:SSLTimeout]
sslContext.min_version      = SSL[:SSLVer] # *IMPORTANT* TLS_1.3

def handle_client(connection)
  puts "[*] New connection #{connection.peeraddr[-1]}:#{connection.peeraddr[1]}" if OPTIONS[:verbose]
  request = connection.readpartial(MAX_BUFFER)

  if request.nil? || request.empty?
    puts '[WARNING] Empty request!' if OPTIONS[:verbose]
    connection.close if connection
    Thread.exit
  end

  request_split = request.split("\r\n")

  if request.match?(/CONNECT/)

    auth_header = request_split.find { |h| h.match(/Authorization/) }
    unless auth_header
      puts '[WARNING] Unauthorized attempt detected (no header provided)!'.red
      connection.close
      Thread.exit
    end
    if auth_header
      auth_key = auth_header.downcase.gsub('authorization:', '').strip
      if auth_key != AUTH_KEY
        puts '[WARNING] Unauthorized attempt detected (wrong auth key)!'.red
        connection.close
        Thread.exit
      end
    end

    endpoint_host, endpoint_port = request_split.first.split(' ')[1].split(':')
    puts "#{endpoint_host}:#{endpoint_port}".green if OPTIONS[:verbose]
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
          buf = connection.readpartial(MAX_BUFFER)
          endpoint_connection.print(buf)
        elsif fds[0].member?(endpoint_connection)
          buf = endpoint_connection.readpartial(MAX_BUFFER)
          connection.print(buf)
        end
      end
    rescue StandardError
      puts "[*] Closing connection with #{endpoint_host}:#{endpoint_port}".red if OPTIONS[:verbose]
      endpoint_connection.close if endpoint_connection
      connection.close if connection
      Thread.exit
    end

  else
    ## GET POST PUT PATCH DELETE ##
    host = request_split[1].downcase.gsub('host:', '').strip
    endpoint_host, endpoint_port = host.split(':')
    endpoint_port = 80 if endpoint_port.nil?
    endpoint_port = endpoint_port.to_i

    if endpoint_host == PUBLIC_IP
      response = "HTTP/1.1 200 OK\r\nServer: #{SERVER_NAME}\r\nContent-Type: text/html\r\n\r\n#{File.read('index.html')}"
      connection.puts(response)
      connection.close
      puts '[LOGS] Webpage is shown, closing the connection...'.green if OPTIONS[:verbose]
      Thread.exit
    end

    auth_header = request_split.find { |h| h.match(/Authorization/) }
    unless auth_header
      puts '[WARNING] Unauthorized attempt detected (no header provided)!'.red
      connection.close
      Thread.exit
    end
    if auth_header
      auth_key = auth_header.downcase.gsub('authorization:', '').strip
      if auth_key != AUTH_KEY
        puts '[WARNING] Unauthorized attempt detected (wrong auth key)!'.red
        connection.close
        Thread.exit
      end
    end

    begin
      endpoint_connection = TCPSocket.new(endpoint_host, endpoint_port)
      puts "#{endpoint_host}:#{endpoint_port}".green if OPTIONS[:verbose]
      endpoint_connection.puts(request)
      response = endpoint_connection.readpartial(MAX_BUFFER)
      connection.puts(response)
      connection.close
      Thread.exit
    rescue StandardError
      puts "#{endpoint_host}:#{endpoint_port}".red if OPTIONS[:verbose]
      connection.puts(CONN_FAIL)
      connection.close if connection
      Thread.exit
    end

  end
end

# The main loop

loop do
  Thread.new(socket.accept) do |connection|
    tls = OpenSSL::SSL::SSLSocket.new(connection, sslContext)
    tls_connection = nil

    Timeout.timeout(10) do
      tls_connection = tls.accept
    end
    if tls_connection
      handle_client(tls_connection) if tls_connection
    else
      connection.close
    end
  rescue Timeout::Error
    connection.close if connection && tls.state == 'PINIT'
  rescue StandardError => e
    puts "[ERROR] #{e}".red if OPTIONS[:verbose]
    connection.close if connection
  end
end
