package dnsserver

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const (
	pidFile           = "/var/run/vpner.pid"
	defaultConfigFile = "/opt/etc/vpner/vpner.yaml"
)

type ServerManager interface {
	Start() error
	Stop() error
	Restart() error
	Status() (string, error)
}

func NewServerManager(configFile string) ServerManager {
	TmpConfigFile := defaultConfigFile
	if len(configFile) > 0 {
		TmpConfigFile = configFile
	}
	return &serverManager{
		configFile: TmpConfigFile,
	}
}

type serverManager struct {
	configFile string
}

func (sm *serverManager) Start() error {
	if isRunning() {
		return fmt.Errorf("сервер уже запущен")
	}
	cmd := exec.Command(os.Args[0], "system", "dns", "server",
		"--config", sm.configFile)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("ошибка запуска команды: %v", err)
	}

	if err := savePID(cmd.Process.Pid); err != nil {
		return fmt.Errorf("ошибка сохранения PID: %v", err)
	}

	return nil
}

func (sm *serverManager) Stop() error {
	pid, err := readPID()
	if err != nil {
		return err
	}

	if pid == 0 {
		return fmt.Errorf("сервер не запущен")
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("ошибка поиска процесса: %v", err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("ошибка отправки сигнала SIGTERM: %v", err)
	}

	if err := os.Remove(pidFile); err != nil {
		return fmt.Errorf("ошибка удаления PID-файла: %v", err)
	}

	return nil
}

func (sm *serverManager) Restart() error {
	if err := sm.Stop(); err != nil {
		return err
	}
	return sm.Start()
}

func (sm *serverManager) Status() (string, error) {
	pid, err := readPID()
	if err != nil {
		return "", err
	}

	if pid == 0 {
		return "Сервер не запущен", nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return "Сервер не запущен", nil
	}

	if err := process.Signal(syscall.Signal(0)); err != nil {
		return "Сервер не запущен", nil
	}

	return fmt.Sprintf("Сервер запущен с PID: %d", pid), nil
}

func isRunning() bool {
	pid, err := readPID()
	if err != nil {
		return false
	}

	if pid == 0 {
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	return process.Signal(syscall.Signal(0)) == nil
}

func savePID(pid int) error {
	if err := os.MkdirAll("/var/run", 0755); err != nil {
		return fmt.Errorf("ошибка создания директории для PID-файла: %v", err)
	}
	file, err := os.Create(pidFile)
	if err != nil {
		return fmt.Errorf("ошибка создания PID-файла: %v", err)
	}
	defer file.Close()

	if _, err := file.WriteString(fmt.Sprintf("%d", pid)); err != nil {
		return fmt.Errorf("ошибка записи PID в файл: %v", err)
	}

	return nil
}

func readPID() (int, error) {
	file, err := os.Open(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("ошибка открытия PID-файла: %v", err)
	}
	defer file.Close()

	var pid int
	if _, err := fmt.Fscanf(file, "%d", &pid); err != nil {
		return 0, fmt.Errorf("ошибка чтения PID из файла: %v", err)
	}

	return pid, nil
}
