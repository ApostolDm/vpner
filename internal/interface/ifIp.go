package manager_interface

import (
	"errors"
	"fmt"
	"net"
)

func FindInterfaceByIP(ipAddress string) (string, error) {
	// Получаем список всех интерфейсов
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("error fetching interfaces: %w", err)
	}

	// Проходим по всем интерфейсам
	for _, iface := range interfaces {
		// Получаем список адресов для каждого интерфейса
		addrs, err := iface.Addrs()
		if err != nil {
			return "", fmt.Errorf("error fetching addresses for interface %s: %w", iface.Name, err)
		}

		// Проходим по каждому адресу интерфейса
		for _, addr := range addrs {
			// Преобразуем адрес в формат IP
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Сравниваем IP-адрес с введённым пользователем
			if ip.String() == ipAddress {
				return iface.Name, nil
			}
		}
	}

	// Если ничего не найдено
	return "", errors.New("no interface found with the given IP address")
}
