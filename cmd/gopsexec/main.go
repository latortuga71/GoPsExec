package main

import (
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/hirochachacha/go-smb2"
	"github.com/latortuga71/gopsexec/pkg/winapi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

//go:embed NamedPipeSvc.exe
var serviceBinary []byte

var user string
var pass string
var domain string
var host string
var command string
var verbose bool

func VerbosePrint(message string) {
	if verbose {
		fmt.Println(message)
	}
}

func LogonUserToAccessSVM(domain, user, pass string) error {
	var hToken syscall.Handle
	ok, err := winapi.LogonUser(user, domain, pass, 9, 3, &hToken)
	if !ok {
		VerbosePrint("[-] Logon User Failed")
		return err
	}
	worked, err := winapi.ImpersonateLoggedOnUser(windows.Token(hToken))
	if !worked {
		VerbosePrint("[-] ImpersonateLoggedOnUser Failed")
		return err
	}
	return nil
}

func main() {
	runtime.LockOSThread()
	flag.StringVar(&user, "u", "", "Username")
	flag.StringVar(&pass, "p", "", "Password")
	flag.StringVar(&domain, "d", ".", "Domain")
	flag.StringVar(&host, "h", "localhost", "Host")
	flag.StringVar(&command, "c", "whoami", "Command to run on target, will be passed like this to cmd.exe /c {yourcommandhere} NOTE command cannot exceed 1000 characters.")
	flag.BoolVar(&verbose, "v", false, "Verbose Flag")
	flag.Parse()
	if user == "" || pass == "" {
		fmt.Printf("Missing User or Pass arguments.\n")
		flag.PrintDefaults()
		return
	}
	if err := LogonUserToAccessSVM(domain, user, pass); err != nil {
		log.Fatal(err)
	}
	VerbosePrint("[+] Logon User Successful.")
	if err := DropServiceBinary(domain, user, pass, host); err != nil {
		log.Fatal(err)
	}
	VerbosePrint("[+] Dropped Service Binary...")
	if err := CreateService(host, "GoPsExec"); err != nil {
		log.Fatal(err)
	}
	VerbosePrint("[+] Created Remote Service...")
	if err := StartService(host, "GoPsExec"); err != nil {
		log.Fatal(err)
	}
	VerbosePrint("[+] Started Serivce....")
	hNamedPipe := ConnectToPipe(fmt.Sprintf("\\\\%s\\pipe\\slotty", host))
	if hNamedPipe == 0 {
		log.Fatal("Couldnt connect to pipe")
	}
	WriteToPipeCommand(hNamedPipe, command)
	VerbosePrint("[+] Reading Results From Pipe...")
	ok, commandOutput := ReadFromPipe(hNamedPipe)
	if !ok {
		VerbosePrint("[-] Failed to get response back from pipe")
	}
	fmt.Printf("%s\n", commandOutput)
	windows.CloseHandle(windows.Handle(hNamedPipe))
	VerbosePrint("[+] Cleaning Up...")
	if err := StopService(host, "GoPsExec"); err != nil {
		log.Fatal(err)
	}
	VerbosePrint("[+] Stopped Service")
	if err := DeleteService(host, "GoPsExec"); err != nil {
		log.Fatal(err)
	}
	VerbosePrint("[+] Deleted Service")
	if err := DeleteServiceBinary(domain, user, pass, host); err != nil {
		log.Fatal(err)
	}
	VerbosePrint("[+] Deleted Service Binary")
	runtime.UnlockOSThread()
}

func ConnectToPipe(pipeName string) uintptr {
	VerbosePrint("[+] Waiting for pipe")
	winapi.WaitNamedPipe(pipeName, 0xffffffff)
	pipeHandle := winapi.CreateFile(pipeName, windows.GENERIC_WRITE|windows.GENERIC_READ, 0, 0, windows.OPEN_EXISTING, 0, 0)
	if pipeHandle == 0 {
		VerbosePrint("[-] Failed to open handle to pipe")
		return 0
	}
	return pipeHandle
}

func ReadFromPipe(handleNamedPipe uintptr) (bool, string) {
	msg := Message{}
	commandResult := ""
	var stopReading bool
	var result string
	var bytesRead uint32
	var buffer [1028]byte
	// read from pipe until we dont need too anymore
	for {
		b := windows.ReadFile(windows.Handle(handleNamedPipe), buffer[:], &bytesRead, nil)
		if b != nil {
			VerbosePrint("[-] Failed to read from pipe")
			return false, ""
		}
		msg.MessageType = binary.LittleEndian.Uint32(buffer[0:4])
		copy(msg.Data[:], buffer[:])
		VerbosePrint(fmt.Sprintf("[+] Read %d Bytes From Pipe\n", bytesRead))
		stopReading, result = HandleResponse(msg)
		commandResult += result
		if stopReading {
			return true, commandResult
		} else {
			continue
		}
	}
}

func HandleResponse(msg Message) (bool, string) {
	result := ""
	for x := 4; x < 1024; x++ {
		if msg.Data[x : x+1][0] == 0 {
			break
		}
		result += string(msg.Data[x : x+1][0])
	}
	if msg.MessageType == 2 {
		return true, result
	}
	return false, result
}

func WriteToPipeCommand(handleNamedPipe uintptr, command string) bool {
	msg := Message{}
	msg.MessageType = 0
	copy(msg.Data[:], []byte(fmt.Sprintf("C:\\Windows\\system32\\cmd.exe /c %s", command)))
	var bytesWritten uint32
	results := winapi.WriteFile(syscall.Handle(handleNamedPipe), uintptr(unsafe.Pointer(&msg)), uint32(unsafe.Sizeof(msg)), &bytesWritten, 0)
	if !results {
		VerbosePrint("[-] Failed to write to pipe")
		return false
	}
	return true
}

type Message struct {
	MessageType uint32
	Data        [1024]byte
}

func StopService(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	service.Control(svc.Stop)
	return nil
}
func StartService(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	service.Start()
	return nil
}
func DeleteService(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	err = service.Delete()
	if err != nil {
		return err
	}
	return nil
}
func CreateService(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	c := mgr.Config{}
	service, err := serviceMgr.CreateService(serviceName, "C:\\Windows\\GoPsExec.exe", c)
	if err != nil {
		return err
	}
	defer service.Close()
	return nil
}

func LogonUser(domain, user, password string) {
	// we need to impersonate before calling sc manager to make it consistent
}

func DeleteServiceBinary(domain, user, pass, targetMachine string) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", targetMachine))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	var d *smb2.Dialer
	d = &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			Domain:   domain,
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return err
	}
	defer s.Logoff()
	share, err := s.Mount("ADMIN$")
	if err != nil {
		return err
	}
	defer share.Umount()
	err = share.Remove("GoPsExec.exe")
	if err != nil {
		return err
	}
	return nil
}

func DropServiceBinary(domain, user, pass, targetMachine string) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", targetMachine))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	var d *smb2.Dialer
	d = &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			Domain:   domain,
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return err
	}
	defer s.Logoff()
	share, err := s.Mount("ADMIN$")
	if err != nil {
		return err
	}
	defer share.Umount()
	err = share.WriteFile("GoPsExec.exe", serviceBinary, 0644)
	if err != nil {
		return err
	}
	return nil
}
