#!/usr/bin/ruby

require 'socket'
require 'openssl'
require 'colorize'
require 'optparse'

ARGV << '-h' if ARGV.empty?

options = {}
OptionParser.new do |opts|
  opts.banner = "TLS Tunnel Client\n\n".bold + 'Usage: ./client.rb [options]'
  opts.on('-v', '--verbose', 'Run verbosely') do |v|
    options[:verbose] = v
  end

  opts.on('-h', '--help', 'Prints help') do
    puts opts
    exit
  end

  opts.on('-aADDR', '--address=ADDR',
          'TLS Tunnel Server address, example: ./client.rb --address example.com') do |addr|
    options[:addr] = addr
  end

  opts.on('-fKEY', '--auth-keyfile=KEY',
          'TLS Tunnel Server authorization key file, example: ./client.rb --auth-keyfile auth_key.txt') do |auth_key|
    options[:auth_key] = auth_key
  end

  opts.on('-pPORT', '--port=PORT',
          'Local port for listening, example: ./client.rb --address example.com --port 8080') do |port|
    options[:port] = port
  end

  opts.on('-sSNI', '--sni=SNI', 'TLS SNI extension spoof, default is [ example.com ] (optional)') do |sni|
    options[:sni] = sni
  end
end.parse!

if !options[:addr] || !options[:port] || !options[:auth_key]
  puts "Please include the server address, authorization key and local port for listening!\nExample: ./client.rb --address/-a example.com --port/-p 8080 --auth-keyfile/-f auth_key.txt".red
  exit
end

unless File.exist?(options[:auth_key])
  puts 'Authentication key file not found!'.red
  exit
end

PROXY_PORT  = options[:port]
SERVER_HOST = options[:addr]
SERVER_PORT = 443 # Don't change this, because the server we are connecting to is supposed to immitate the real https connection
SNI_HOST	= options[:sni] || 'example.com' # SNI SPOOFING
TTL	= 10 # 10 SEC
MAX_BUFFER = 1024 * 640 # 640KB
AUTH_KEY	= File.read(options[:auth_key]).chomp

def connect(host, port)
  begin
    socket = TCPSocket.new(host, port)
    return nil unless socket

    sslContext = OpenSSL::SSL::SSLContext.new
    sslContext.min_version = OpenSSL::SSL::TLS1_3_VERSION
    ssl = OpenSSL::SSL::SSLSocket.new(socket, sslContext)
    ssl.hostname = SNI_HOST
    ssl.sync_close = true
    ssl.connect
  rescue StandardError
    puts '[WARNING] TLS Tunnel Server seems to be down'.red
    return nil
  end
  ssl
end

def is_alive?(ssl, payload)
  payload = payload.gsub("\r\n\r\n", "\r\nAuthorization: #{AUTH_KEY}\r\n\r\n")
  ssl.puts(payload)
  begin
    response = ssl.readpartial(MAX_BUFFER)
  rescue StandardError
    return nil
  end
  response
end

proxy = TCPServer.new(PROXY_PORT)
puts "[#{Time.now}] Listening on #{PROXY_PORT}".bold

loop do
  connection = proxy.accept
  Thread.new do
    request = connection.recv(MAX_BUFFER)
    Thread.exit if request.size < 1 || request.empty? || request.nil?
    request_head = request.split("\r\n")
    request_method = request_head.first.split(' ')[0] # CONNECT, GET, POST

    if request_method =~ /CONNECT/
      ssl = connect(SERVER_HOST, SERVER_PORT)
      Thread.exit unless ssl
      request_host, request_port = request_head.first.split(' ')[1].split(':')
      if header = is_alive?(ssl, request)
        puts "[CONNECT] #{request_host}:#{request_port}".green if options[:verbose]
        connection.puts(header)
      else
        puts "[CONNECT] #{request_host}:#{request_port} is unavailable!".red if options[:verbose]
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
      rescue StandardError
        puts "[INFO] Closing connection with #{request_host}:#{request_port}".red if options[:verbose]
        ssl.close if ssl
        connection.close if connection
        Thread.exit
      end

    else
      # GET POST PUT POST PATCH DELETE ETC#
      ssl = connect(SERVER_HOST, SERVER_PORT)
      Thread.exit unless ssl

      method = request.split("\n")[0]
      host = request.split("\n")[1].downcase.gsub('host:', '').strip
      request_host, request_port = host.split(':')
      request_port = 80 if request_port.nil?
      request_port = request_port.to_i

      request = request.gsub("\r\n\r\n", "\r\nAuthorization: #{AUTH_KEY}\r\n\r\n")
      ssl.puts(request)
      begin
        response = ssl.readpartial(MAX_BUFFER)
        connection.puts(response)
        puts "[NON-CONNECT] #{request_host}:#{request_port}".green if options[:verbose]
      rescue StandardError
        puts "[NON-CONNECT] #{request_host}:#{request_port}".red if options[:verbose]
      ensure
        connection.close
      end
    end
  end
end
