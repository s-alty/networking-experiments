package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
)


const (
	_workerSockName = "worker.sock"
	_transferInbandMsg = "transferring"
)

func socketTransferPitch(unixSock *net.UnixConn, sock *net.TCPConn) error {
	rawConn, err := sock.SyscallConn()
	if err != nil {
		return err
	}

	var oobPayload []byte
	err = rawConn.Control(func(fd uintptr) {
		oobPayload = syscall.UnixRights(int(fd))
	})
	if err != nil {
		return err
	}

	ra := unixSock.RemoteAddr()
	_, _, err = unixSock.WriteMsgUnix([]byte("transferring"), oobPayload, &net.UnixAddr{Net: ra.Network(), Name: ra.String()})
	return err
}

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:1915")
	if err != nil {
		panic(err)
	}

	workerSock, err := net.Dial("unix", _workerSockName)
	if err != nil {
		panic(err)
	}

	workerSockUnix := workerSock.(*net.UnixConn)
	fmt.Printf("local: %v\n", workerSockUnix.LocalAddr())
	fmt.Printf("remote: %v\n", workerSockUnix.RemoteAddr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("accept err: %v\n", err)
			continue
		}

		conn.Write([]byte(fmt.Sprintf("accepted by process %d\n", os.Getpid())))
		tcpConn = conn.(*net.TCPConn)
		err = socketTransferPitch(workerSockUnix, tcpConn)
		if err != nil {
			fmt.Printf("transfer err: %v\n", err)
		}
		conn.Close()
	}
}
