package hook

import (
	"fmt"
	"os"
	"strings"

	"github.com/ApostolDmitry/vpner/internal/utils"
	"github.com/spf13/cobra"
)

func hookIfDestroyed() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ifdestroyed",
		Short: "Обработка данных при удалении интерфейса.",
		Run: func(cmd *cobra.Command, args []string) {
			message := strings.Join(args, " ")
			envVars := os.Environ()
			envVarsString := strings.Join(envVars, "\n")
			logMessage := fmt.Sprintf("Аргументы: %s\nПеременные окружения:\n%s", message, envVarsString)

			if err := utils.Log("ifdestroyed", logMessage); err != nil {
				fmt.Printf("Ошибка записи в лог: %v\n", err)
			}
		},
	}
	return cmd
}
