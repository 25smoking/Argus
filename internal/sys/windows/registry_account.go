//go:build windows

package winsys

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

type RegistryValue struct {
	Name  string
	Value string
}

type UserAccountInfo struct {
	Name  string
	SID   string
	RID   uint32
	Flags uint32
	Priv  uint32
}

func ReadRegistryValues(root registry.Key, subPath string) ([]RegistryValue, error) {
	key, err := registry.OpenKey(root, subPath, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	values := make([]RegistryValue, 0, len(names))
	for _, name := range names {
		if val, _, err := key.GetStringValue(name); err == nil {
			values = append(values, RegistryValue{Name: name, Value: val})
			continue
		}
		if vals, _, err := key.GetStringsValue(name); err == nil {
			values = append(values, RegistryValue{Name: name, Value: fmt.Sprint(vals)})
		}
	}
	return values, nil
}

func ReadRegistryStringValue(root registry.Key, subPath, valueName string) (string, error) {
	key, err := registry.OpenKey(root, subPath, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()
	val, _, err := key.GetStringValue(valueName)
	return val, err
}

func EnumRegistrySubkeys(root registry.Key, subPath string) ([]string, error) {
	key, err := registry.OpenKey(root, subPath, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	return key.ReadSubKeyNames(-1)
}

func EnumLocalUsers() ([]UserAccountInfo, error) {
	return nil, errors.New("EnumLocalUsers native implementation is not available in this build")
}
