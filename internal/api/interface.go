package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	manager_interface "github.com/ApostolDmitry/vpner/internal/interface"
)

const (
	interfaceStatusURL  = "http://127.0.0.1:79/rci/show/interface"
	interfaceControlURL = "http://127.0.0.1:79/rci/interface"
)

// InterfaceState представляет состояние интерфейса
type InterfaceState struct {
	State string `json:"state"`
}

// FetchInterfaces запрашивает список интерфейсов
func FetchInterfaces() (map[string]manager_interface.Interface, error) {
	resp, err := http.Get(interfaceStatusURL)
	if err != nil {
		return nil, fmt.Errorf("ошибка при запросе интерфейсов: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ошибка при чтении ответа: %v", err)
	}

	var interfacesMap map[string]manager_interface.Interface
	err = json.Unmarshal(body, &interfacesMap)
	if err != nil {
		return nil, fmt.Errorf("ошибка при парсинге интерфейсов: %v", err)
	}

	return interfacesMap, nil
}

// RestartVPNConnection перезапускает VPN-соединение для указанного интерфейса с задержкой
func RestartVPNConnection(interfaceName string, delayBetweenRestart int) error {
	// Получаем текущее состояние интерфейса
	currentState, err := getInterfaceState(interfaceName)
	if err != nil {
		return err
	}

	// Проверяем состояние ISP соединения
	ispState, err := getISPState()
	if err != nil {
		return err
	}

	if ispState == "down" {
		return fmt.Errorf("проверьте соединение с провайдером и/или настройки DNS")
	}

	// Переключаем состояние интерфейса
	if currentState == "up" {
		if err := setInterfaceState(interfaceName, "down"); err != nil {
			return err
		}
	} else {
		if err := setInterfaceState(interfaceName, "up"); err != nil {
			return err
		}
	}

	// Задержка перед возвратом в исходное состояние
	time.Sleep(time.Duration(delayBetweenRestart) * time.Second)

	// Возвращаем интерфейс в исходное состояние
	if err := setInterfaceState(interfaceName, currentState); err != nil {
		return err
	}

	return nil
}

// getInterfaceState возвращает текущее состояние указанного интерфейса
func getInterfaceState(interfaceName string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/%s", interfaceControlURL, interfaceName))
	if err != nil {
		return "", fmt.Errorf("ошибка при запросе состояния интерфейса: %v", err)
	}
	defer resp.Body.Close()

	var state InterfaceState
	err = json.NewDecoder(resp.Body).Decode(&state)
	if err != nil {
		return "", fmt.Errorf("ошибка при парсинге состояния интерфейса: %v", err)
	}

	return state.State, nil
}

// getISPState возвращает текущее состояние ISP соединения
func getISPState() (string, error) {
	resp, err := http.Get(interfaceStatusURL)
	if err != nil {
		return "", fmt.Errorf("ошибка при запросе состояния ISP: %v", err)
	}
	defer resp.Body.Close()

	var interfaces []manager_interface.Interface
	err = json.NewDecoder(resp.Body).Decode(&interfaces)
	if err != nil {
		return "", fmt.Errorf("ошибка при парсинге состояния ISP: %v", err)
	}

	for _, iface := range interfaces {
		if iface.DefaultGW && iface.Global {
			return iface.State, nil
		}
	}

	return "down", nil
}

// setInterfaceState изменяет состояние указанного интерфейса
func setInterfaceState(interfaceName, desiredState string) error {
	requestBody := map[string]string{desiredState: "true"}
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("ошибка при создании JSON для запроса: %v", err)
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", interfaceControlURL, interfaceName), bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("ошибка при создании запроса: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ошибка при выполнении запроса: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("сервер вернул ошибку: %s", resp.Status)
	}

	return nil
}
