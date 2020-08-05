# IDEA-HMK-Cryptor

Project consists of 3 main parts:   
1.	IDEA for message encryption and decryption.  
2.	Merkle–Hellman knapsack for key transmission.  
3.	implementation of Digital Signature algorithm.  
The main idea of the project is to be able to securely transmit and verify messages between 2 parties sender and receiver via a server inbetween that transmits/receives only encrypted data.  

Project consists of 3 algorithms and each containing its own sample program,a simple Sender-Server-Receiver framework is implemented to illustrate and log key/cipher transmission stages in a real-life scenario, that creates a socket passing HMK public key to the sender in order to  sign and encrypt it and transmit it back to the receiver(decrypts and verifies) so both parties have the same symmetric encryption/decryption key avoiding prying eyes inbetween both ends.   
After securing key transmission both parties Sender and Receiver are ready to communicate so the sender can sign original message, encrypt it and send to the server to pass it to the receiver whom decrypts and verifies that original message has not been altered.  
  
  *Project contains 2 interfaces Console(MainProgramConsole.py) and GUI(MainProgramGUI.py)

Output:
Secure transmission illustration between sender and receiver which they are encryption and decryption of the messages using IDEA and digital signature to sign and verify + key transimission using Merkle–Hellman knapsack for key transmission.

Flow:
![Code Flow](https://github.com/adam-mah/IDEA-HMK-Cryptor/blob/master/img/Flow.jpg?raw=true)

GUI and Output:  
![Code GUI](https://github.com/adam-mah/IDEA-HMK-Cryptor/blob/master/img/GUI.png)
![Code Output](https://github.com/adam-mah/IDEA-HMK-Cryptor/blob/master/img/Data.png?raw=true)  
  
  
  
 By Adam Mahameed, Karam Abu Mokh  
   
   MIT LICENSE:
   
   Copyright (c) 2020 Adam Mahameed

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
