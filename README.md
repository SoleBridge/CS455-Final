# Overview:
- What is the problem you're trying to solve?
  - The prupose of this program is demonstrate how to create an encrypted and authenticated client-server message program.
- How did you solve it?
  - This program uses sockets for communication and OpenSSL for encryption / decryption and server authentication.
  - The program is implemented in C.
- Why are you working on this problem?
  - Originally, the plan was to create custom packets and encryption. But available libraries performed these actions better.
  - So, I decided to change to a demo program which can show students / developers how to use sockets and OpenSSL.
- Other proposed features:
  - Originally, I proposed to create custom packets and encryption algorithms, and to test their performance against other well-used algoritms.
  - However, I switched to using OpenSSL, and creating a simple demo program, more for teaching purposes than actual use.
---
# Build and Run:
- Note: This code has only been tested on Arch Linux.
## Certificate Generation
- Enter the following command, and follow the prompts to generate the required authentication files:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt
```
## Compilation
- Compile the program with:
```bash
gcc main.c -o encrypted-demo -lssl -lcrypto
```
## Starting a Server
- Start a server with:
```bash
encrypted-demo server
```
- This will start a server on localhost IP, port 8080.
## Starting a Client
- After the server is started, start a client with:
```bash
encrypted-demo client
```
- If an IP is not specified, it will default to localhost, port 8080.
## Using the Application
- In the client, enter messages.
- These mesages will be encrypted and shown to the user.
- Then the encrypted message will be sent to the server, decrypted, and shown on the server terminal.
- Then the server will form a response (echo), and send this back to the client.
- The echo message will be displayed on the client.
- Enter another message.
---
# Demo
- Application demo [YouTube video](youtube.com).
