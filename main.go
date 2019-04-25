package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

func main() {
	conn, err := net.Dial("tcp", "<host>:<port>")
	if err != nil {
		fmt.Println(err)
		return
	}

	banner_bytes := make([]byte, 100)
	_, err2 := conn.Read(banner_bytes)
	if err2 != nil {
		if err2 != io.EOF {
			fmt.Println("read error:", err2)
		}
	}

	banner_bytes = bytes.Replace(banner_bytes, []byte{10}, []byte{}, -1)
	banner_bytes = bytes.Replace(banner_bytes, []byte{13}, []byte{}, -1)

	fmt.Println(string(banner_bytes))

	conn.Write([]byte("SSH-2.0-OpenSSH-CipherScan\r\n"))

	tmp := make([]byte, 2048)
	_, err3 := conn.Read(tmp)
	if err3 != nil {
		if err3 != io.EOF {
			fmt.Println("read error:", err3)
		}
	}

	kex_algorithms := []string{}
	server_host_key_algorithms := []string{}
	encryption_algorithms := []string{}
	mac_algorithms := []string{}
	compression_algorithms := []string{}

	//__packet_length__   := tmp[0:4]
	//__padding_length__  := tmp[4]
	//__SSH_MSG_KEXINIT__ := tmp[5]
	//__cookie__          := tmp[6:22]

	payload_start := 4 + 1 + 1 + 16
	payload := tmp[payload_start:]
	payload = bytes.TrimRight(payload, string([]byte{0x00}))

	current_pointer := uint32(0)

	for _, cipher := range []string{
		"kex_algorithms",
		"server_host_key_algorithms",
		"encryption_algorithms_client_to_server",
		"encryption_algorithms_server_to_client",
		"mac_algorithms_client_to_server",
		"mac_algorithms_server_to_client",
		"compression_algorithms_client_to_server",
		"compression_algorithms_server_to_client"} {

		cipher_length := binary.BigEndian.Uint32(payload[current_pointer : current_pointer+4])
		ciphers := payload[current_pointer+4 : current_pointer+cipher_length+4]
		current_pointer += cipher_length + 4

		if strings.Contains(cipher, "server_to_client") || strings.HasSuffix(cipher, "algorithms") {
			if strings.Contains(cipher, "kex_algorithms") {
				kex_algorithms = strings.Split(string(ciphers), ",")
			}

			if strings.Contains(cipher, "server_host_key_algorithms") {
				server_host_key_algorithms = strings.Split(string(ciphers), ",")
			}

			if strings.Contains(cipher, "encryption_algorithms") {
				encryption_algorithms = strings.Split(string(ciphers), ",")
			}

			if strings.Contains(cipher, "mac_algorithms") {
				mac_algorithms = strings.Split(string(ciphers), ",")
			}

			if strings.Contains(cipher, "compression_algorithms") {
				compression_algorithms = strings.Split(string(ciphers), ",")
			}
		}
	}

	fmt.Println(kex_algorithms)
	fmt.Println(server_host_key_algorithms)
	fmt.Println(encryption_algorithms)
	fmt.Println(mac_algorithms)
	fmt.Println(compression_algorithms)
}
