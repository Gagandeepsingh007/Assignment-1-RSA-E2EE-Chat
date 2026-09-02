# E2EE Chat using a server
### This is a End to End Encrypted (E2EE) chat project which is done a a part of my university course, here is how it works:
```
1. I start the server.py file and which uses socket and threading libraries.
2. I make a client using the client.py file, then a second one using the same client.py file in a separate command window.
3. Initially they are chatting using the RSA encryption which is very secure but not as fast as AES.
4. One user initiates the AES encryption using a keyword, which generates a AES key then sends it to the second user.
5. Rest of the conversation is done using AES Encryption which is faster and also the current standard. 
```

### Here is a video link showing the project working
```
https://youtu.be/oQG2nRT60rg
```
