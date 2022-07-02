package winapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const NMPWAIT_WAIT_FOREVER = 0xffffffff

var (
	kernel32dll                 = syscall.NewLazyDLL("kernel32.dll")
	wtsapi32dll                 = syscall.NewLazyDLL("Wtsapi32.dll")
	advapi32                    = syscall.NewLazyDLL("Advapi32.dll")
	pReadFile                   = kernel32dll.NewProc("ReadFile")
	pWriteFile                  = kernel32dll.NewProc("WriteFile")
	pWaitNamedPipe              = kernel32dll.NewProc("WaitNamedPipeW")
	pCreateFile                 = kernel32dll.NewProc("CreateFileW")
	pFlushFileBuffers           = kernel32dll.NewProc("FlushFileBuffers")
	pAllocConsole               = kernel32dll.NewProc("AllocConsole")
	pGetActiveConsoleSessionsId = kernel32dll.NewProc("WTSGetActiveConsoleSessionId")
	pDisconnectNamedPipe        = kernel32dll.NewProc("DisconnectNamedPipe")
	pWTSSendMessage             = wtsapi32dll.NewProc("WTSSendMessageW")
	pLogonUser                  = advapi32.NewProc("LogonUserW")
	pImpersonateLoggedOnUser    = advapi32.NewProc("ImpersonateLoggedOnUser")
)

func ImpersonateLoggedOnUser(token windows.Token) (bool, error) {
	worked, _, err := pImpersonateLoggedOnUser.Call(uintptr(token))
	if worked == 0 {
		return false, err
	}
	return true, nil
}

func LogonUser(user string, domain string, password string, logonType uint32, logonProvider uint32, hToken *syscall.Handle) (bool, error) {
	userPtr := syscall.StringToUTF16Ptr(user)
	domainPtr := syscall.StringToUTF16Ptr(domain)
	passPtr := syscall.StringToUTF16Ptr(password)
	res, _, err := pLogonUser.Call(uintptr(unsafe.Pointer(userPtr)), uintptr(unsafe.Pointer(domainPtr)), uintptr(unsafe.Pointer(passPtr)), uintptr(logonType), uintptr(logonProvider), uintptr(unsafe.Pointer(hToken)))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func DisconnectNamedPipe(handle windows.Handle) bool {
	res, _, _ := pDisconnectNamedPipe.Call()
	if res == 0 {
		return false
	}
	return true
}

func WTSGetActiveConsoleSessionId() uint32 {
	res, _, _ := pGetActiveConsoleSessionsId.Call()
	return uint32(res)
}

func WTSSendMessage(handle uintptr, sessionid uint32, title string, titleLen uint32, message string, messageLen uint32, style uint32, timeout uint32, response *uint32, bwait bool) bool {
	titleptr := syscall.StringToUTF16Ptr(title)
	messagePtr := syscall.StringToUTF16Ptr(message)
	res, _, _ := pWTSSendMessage.Call(handle, uintptr(sessionid), uintptr(unsafe.Pointer(titleptr)), uintptr(titleLen), uintptr(unsafe.Pointer(messagePtr)), uintptr(messageLen), uintptr(style), uintptr(timeout), uintptr(unsafe.Pointer(response)), 0)
	if res == 0 {
		return false
	}
	return true
}

func AllocConsole() bool {
	res, _, _ := pAllocConsole.Call()
	if res == 0 {
		return false
	}
	return true
}

func ReadFile(handle syscall.Handle, lpBuffer uintptr, bytesToRead uint32, numberOfBytesRead *uint32, lpOverlapped uintptr) bool {
	result, _, _ := pWriteFile.Call(uintptr(handle), lpBuffer, uintptr(bytesToRead), uintptr(unsafe.Pointer(numberOfBytesRead)), lpOverlapped)
	if result == 0 {
		return false
	}
	return true
}

func WriteFile(handle syscall.Handle, lpBuffer uintptr, bytesToWrite uint32, numberOfBytesWritten *uint32, lpOverlapped uintptr) bool {
	result, _, _ := pWriteFile.Call(uintptr(handle), lpBuffer, uintptr(bytesToWrite), uintptr(unsafe.Pointer(numberOfBytesWritten)), lpOverlapped)
	if result == 0 {
		return false
	}
	return true
}

func CreateFile(lpFileName string, desiredAccess uint32, dwShareMode uint32, lpSecuityAttributes uintptr, dwCreationDisposition uint32, dwFlags uint32, hTemplateFile uintptr) uintptr {
	lpFileNamePtr, err := syscall.UTF16PtrFromString(lpFileName)
	if err != nil {
		return 0
	}
	handle, _, _ := pCreateFile.Call(uintptr(unsafe.Pointer(lpFileNamePtr)), uintptr(desiredAccess), uintptr(dwShareMode), lpSecuityAttributes, uintptr(dwCreationDisposition), uintptr(dwFlags), hTemplateFile)
	if handle == 0 {
		return 0
	}
	return handle
}

func WaitNamedPipe(pipeName string, timout uint32) int {
	ptr, err := syscall.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0
	}
	_, _, _ = pWaitNamedPipe.Call(uintptr(unsafe.Pointer(ptr)), uintptr(timout))
	return 1
}

func FlushFileBuffers(handle syscall.Handle) bool {
	res, _, _ := pFlushFileBuffers.Call(uintptr(handle))
	return res != 0
}
