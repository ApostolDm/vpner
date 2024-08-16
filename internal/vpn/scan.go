package vpn

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/api"
	manager_interface "github.com/ApostolDmitry/vpner/internal/interface"
	"github.com/fatih/color"
)

func ScanInterfaces() error {
	defaultManager := manager_interface.NewInterfaceManager("")
	interfacesMap, err := api.FetchInterfaces()
	if err != nil {
		return err
	}

	vpnInterfaces := filterVPNInterfaces(interfacesMap, getVPNTypes())
	if len(vpnInterfaces) == 0 {
		color.Yellow("Активные VPN интерфейсы не найдены.")
		return nil
	}

	addedInterfaces, err := defaultManager.ReadAddedInterfaces()
	if err != nil {
		return err
	}

	ids := displayInterfaces(vpnInterfaces, addedInterfaces)

	choice, err := getUserChoice(len(ids))
	if err != nil {
		return err
	}

	selectedID := ids[choice-1]
	selectedIface := vpnInterfaces[selectedID]

	action := "добавлен"
	if isAdded(selectedID, addedInterfaces) {
		action = "удалён"
	}

	err = defaultManager.AddOrRemoveInterface(selectedID, selectedIface)
	if err != nil {
		return fmt.Errorf("ошибка при обновлении файла: %v", err)
	}

	color.Green("Интерфейс %s (%s) был %s для перенаправления трафика.\n", selectedID, selectedIface.Type, action)
	return nil
}

func getVPNTypes() map[string]bool {
	return map[string]bool{
		"OpenVPN":   true,
		"Wireguard": true,
		"IKE":       true,
		"SSTP":      true,
		"PPPOE":     true,
		"L2TP":      true,
		"PPTP":      true,
	}
}

func filterVPNInterfaces(interfacesMap map[string]manager_interface.Interface, vpnTypes map[string]bool) map[string]manager_interface.Interface {
	vpnInterfaces := make(map[string]manager_interface.Interface)
	for id, iface := range interfacesMap {
		if vpnTypes[iface.Type] {
			vpnInterfaces[id] = iface
		}
	}
	return vpnInterfaces
}

func displayInterfaces(vpnInterfaces map[string]manager_interface.Interface, addedInterfaces map[string]bool) []string {
	fmt.Println("Доступные VPN интерфейсы:")

	var ids []string
	for id := range vpnInterfaces {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for i, id := range ids {
		iface := vpnInterfaces[id]
		status := "Активен"
		if iface.State != "up" {
			status = "Отключен"
		}
		added := ""
		if addedInterfaces[id] {
			added = " (уже добавлен)"
		}
		color.Cyan("%2d. ID: %-15s Тип: %-10s Статус: %-9s%s", i+1, id, iface.Type, status, added)
	}

	return ids
}

func getUserChoice(max int) (int, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Введите номер интерфейса для добавления/удаления: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		var choice int
		_, err := fmt.Sscanf(input, "%d", &choice)
		if err != nil || choice < 1 || choice > max {
			color.Red("Некорректный выбор. Введите число от 1 до %d.", max)
			continue
		}
		return choice, nil
	}
}

func isAdded(id string, addedInterfaces map[string]bool) bool {
	return addedInterfaces[id]
}
