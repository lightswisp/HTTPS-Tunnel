
## Basic Demonstration

![App Screenshot](https://blog.devart.com/wp-content/uploads/2015/01/tunneling-dgram.png)

## Demo

![Gif](https://github.com/lightswisp/HTTPS-Tunnel/blob/main/demo.gif)


## Why do you even need to use it?

- To bypass restrictions (like firewall or proxy that filters your traffic)
- To bypass DPI
- To add additional layer of encryption
- To mask your internet activity from your ISP (ISP couldn't see what websites you're visiting because the actual TLS traffic is encapsulated inside another TLS Context)

## Good to know

TLS/SSL (Transport Layer Security/Secure Sockets Layer) is a security protocol that allows for the encryption of data transmitted over the internet between two endpoints, such as a web browser and a web server.

A TLS/SSL tunnel is a secure communication pathway established between a client and a server using TLS/SSL protocol. When a client initiates a connection to a server, the server sends its SSL certificate to the client, which contains the public key used for encryption. The client then generates a random key and encrypts it using the server's public key, sending it back to the server.

Once the server receives the encrypted key from the client, it decrypts it using its private key and establishes a secure session with the client. From that point on, all data transmitted between the two endpoints is encrypted using the shared secret key, ensuring that it cannot be intercepted or read by any third party.
## How does it work

Once the browser sends a request to the local Tunnel Client, the local Tunnel Client sends a CONNECT method to verify that the host is functioning, and then the communication begins. The client transmits encrypted data over an additional layer of TLS, effectively creating a TLS-over-TLS scenario. The tunnel server relays the TLS-encrypted data to the endpoint server and sends the response back until the communication ends (EOF or IO.select throws an exception).
## How to run

In order to intall and run it, you need to have a dedicated server that will play the role of the tunneling server. Also you need to install Ruby on the both server and client machines.

**On the server**

```
git clone https://github.com/lightswisp/HTTPS-Tunnel.git
cd HTTPS-Tunnel
bundle install
ruby server.rb
```

**On the client**

```
git clone https://github.com/lightswisp/HTTPS-Tunnel.git
cd HTTPS-Tunnel
bundle install
ruby client.rb
```

Now, your local tunnel is listening on port 8080. Go and set it up in the firefox browser.

**Configuring the tunnel in the browser**

    1. Go to about:preferences
    2. Then search for 'proxy'
    3. Click on settings
    4. Select 'Manual proxy configuration'
    5. Type 127.0.0.1 for ip, and 8080 for port
    6. Select 'Also use for HTTPS'
    7. Click OK
