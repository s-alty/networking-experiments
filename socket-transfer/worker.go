package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
)


const (
	_workerSockName = "worker.sock"
	_transferredConnName = "transferred-client-connection"
)

func socketTransferCatch(unixSock *net.UnixConn) (net.Conn, error) {
	data := make([]byte, 2048)
	oob := make([]byte, 2048)

	_, oobn, _, addr, err := unixSock.ReadMsgUnix(data, oob)
	if err != nil {
		return nil, err
	}

	fmt.Printf("recvmsg from %v\n", addr)
	controlMessages, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		fmt.Printf("couldnt parse control messages\n")
		return nil, err
	}

	if len(controlMessages) == 0 {
		return nil, fmt.Errorf("No control messages were present")
	}
	if len(controlMessages) > 1 {
		fmt.Printf("Warning, unhandled control messages\n")
	}

	fds, err := syscall.ParseUnixRights(&controlMessages[0])
	if err != nil {
		fmt.Printf("couldnt parse fd from control message\n")
		return nil, err
	}

	if len(fds) == 0 {
		return nil, fmt.Errorf("No file descriptors were present on control message")
	}
	if len(fds) > 1 {
		fmt.Printf("Warning, multiple file descriptors transferred in single call")
	}
	file := os.NewFile(uintptr(fs[0]), _transferredConnName)
	return net.FileConn(file)
}

func service(c net.Conn) {
	defer c.Close()
	fmt.Printf("Got transferred connection from %v\n", c.RemoteAddr())
	c.Write([]byte(fmt.Sprintf("servicing connection in process %d\n", os.Getpid())))
}

func main() {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: _workerSockName})
	if err != nil {
		panic(err)
	}

	unixConn, err := listener.AcceptUnix()
	if err != nil {
		panic(err)
	}

	for {
		conn, err := socketTransferCatch(unixConn)
		if err != nil {
			fmt.Printf("error receiving socket fd from client\n %v", err)
			continue
		} else {
			go service(conn)
		}

	}
}
