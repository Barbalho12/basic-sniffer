# Sniffer

Program for monitoring network packets

### Download libpcap

```sh
sudo apt-get install libpcap-dev
```

### Compiling

```sh
# Compiling sniffer
gcc sniffer.c -lpcap -o sniffer

# Compiling senders for each pattern
gcc send1.c -o send1
gcc send2.c -o send2
```

### Running

```sh
# Terminal 1
sudo ./sniffer lo


# Terminal 2
sudo ./send1 # Pattern with menssage type 1
sudo ./send1 # Or Pattern with menssage type 2

```


<!-- 	
gcc sniffer.c -lpcap -o sniffer && sudo ./sniffer lo
gcc send2.c -o send2 && sudo ./send2
gcc send1.c -o send1 && sudo ./send1 
-->

<!-- https://www.binarytides.com/packet-sniffer-code-c-linux/ -->
