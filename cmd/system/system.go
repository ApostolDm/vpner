package system

import (
	"github.com/ApostolDmitry/vpner/cmd/system/dns"
	"github.com/ApostolDmitry/vpner/cmd/system/hook"
	"github.com/ApostolDmitry/vpner/cmd/system/initsystem"
	"github.com/spf13/cobra"
)

var systemCmd = &cobra.Command{
	Use:    "system",
	Short:  "Это системные команды, они обрабатываются самим роутером. [БЕЗ ПОНИМАНИЯ КАК ЭТО РАБОТАЕТ СЮДА НЕ ЛЕЗЬТЕ]",
	Hidden: true,
}

func Init() {
	dns.Init()
	hook.Init()
	systemCmd.AddCommand(dns.GetDNSCommand())
	systemCmd.AddCommand(hook.GetHookCommand())
	systemCmd.AddCommand(initsystem.InitSystem())
}

func GetSystemCommand() *cobra.Command {
	return systemCmd
}
