package winsys

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modwintrust        = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = modwintrust.NewProc("WinVerifyTrust")
)

const (
	WTD_UI_NONE                           = 2
	WTD_REVOKE_NONE                       = 0x00000000
	WTD_CHOICE_FILE                       = 1
	WTD_STATEACTION_VERIFY                = 0x00000001
	WTD_SA_IGNORE_REVOCATION_CHECKS_TOTAL = 0x00000020 // Optimize speed
)

var (
	WINTRUST_ACTION_GENERIC_VERIFY_V2 = syscall.GUID{
		Data1: 0x00aac56b,
		Data2: 0xcd44,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
	}
)

type WINTRUST_FILE_INFO struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          syscall.Handle
	pgKnownSubject *syscall.GUID
}

type WINTRUST_DATA struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr // LPVOID
	pSIPClientData      uintptr // LPVOID
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pInfoStruct         uintptr // Pointer to WINTRUST_FILE_INFO
	dwStateAction       uint32
	hWVTStateData       uintptr
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// VerifySignature 验证指定文件的数字签名
// 返回 nil 表示验证通过，否则返回错误
func VerifySignature(filePath string) error {
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return err
	}

	fileInfo := WINTRUST_FILE_INFO{
		cbStruct:       uint32(unsafe.Sizeof(WINTRUST_FILE_INFO{})),
		pcwszFilePath:  pathPtr,
		hFile:          0,
		pgKnownSubject: nil,
	}

	trustData := WINTRUST_DATA{
		cbStruct:            uint32(unsafe.Sizeof(WINTRUST_DATA{})),
		dwUIChoice:          WTD_UI_NONE,
		fdwRevocationChecks: WTD_REVOKE_NONE,
		dwUnionChoice:       WTD_CHOICE_FILE,
		pInfoStruct:         uintptr(unsafe.Pointer(&fileInfo)),
		dwStateAction:       WTD_STATEACTION_VERIFY,
		dwProvFlags:         0, // Try default flags to ensure Catalog lookup works
	}

	// WinVerifyTrust returns 0 (ERROR_SUCCESS) if verified
	ret, _, _ := procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&WINTRUST_ACTION_GENERIC_VERIFY_V2)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	if ret == 0 {
		return nil
	}

	// 0x800B0100 = TRUST_E_NOSIGNATURE
	if ret == 0x800B0100 {
		return fmt.Errorf("No signature was present in the subject")
	}

	// 0x80096010 = TRUST_E_BAD_DIGEST
	if ret == 0x80096010 {
		return fmt.Errorf("The digital signature of the object did not verify (Bad Digest)")
	}

	return fmt.Errorf("Verification failed with error: 0x%x", ret)
}
