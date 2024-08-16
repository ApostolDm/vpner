package dns

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ApostolDmitry/vpner/internal/dnsserver"
	"github.com/ApostolDmitry/vpner/internal/dohclient"
	"github.com/ApostolDmitry/vpner/internal/network"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type serverConfig struct {
	Port           int                 `yaml:"port"`
	DoHServers     []string            `yaml:"doh-servers"`
	DoHResolveTTL  int                 `yaml:"doh-resolve-ttl"`
	DNSResolvers   []string            `yaml:"dns-resolvers"`
	MaxConnections int                 `yaml:"max-connections"`
	CustomResolve  map[string][]string `yaml:"custom-resolve"`
	Verbose        bool                `yaml:"verbose"`
}

type vpnConfig struct {
	DNSServer serverConfig `yaml:"dnsServer"`
}

func dnsServer() *cobra.Command {
	var config vpnConfig
	var configFile string

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Запускает DNS-прокси с YAML-конфигом и возможностью переопределения через флаги",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configFile == "" {
				return fmt.Errorf("нужно указать путь к конфигурационному файлу через --config")
			}

			data, err := os.ReadFile(configFile)
			if err != nil {
				return fmt.Errorf("не удалось прочитать конфигурационный файл: %w", err)
			}

			if err := yaml.Unmarshal(data, &config); err != nil {
				return fmt.Errorf("ошибка парсинга YAML: %w", err)
			}
			if config.DNSServer.Port <= 0 || config.DNSServer.Port > 65535 {
				return fmt.Errorf("некорректный порт: %d", config.DNSServer.Port)
			}
			if len(config.DNSServer.DoHServers) == 0 {
				return fmt.Errorf("не указан ни один DoH сервер")
			}
			if config.DNSServer.DoHResolveTTL <= 0 {
				return fmt.Errorf("некорректное время кэширования: %d", config.DNSServer.DoHResolveTTL)
			}
			if len(config.DNSServer.DNSResolvers) == 0 {
				return fmt.Errorf("не указан ни один DNS резолвер")
			}
			if config.DNSServer.MaxConnections <= 0 {
				return fmt.Errorf("максимальное количество подключений должно быть больше 0")
			}

			if cmd.Flags().Changed("port") {
				config.DNSServer.Port, _ = cmd.Flags().GetInt("port")
			}
			if cmd.Flags().Changed("doh-servers") {
				s, _ := cmd.Flags().GetString("doh-servers")
				config.DNSServer.DoHServers = strings.Split(s, ",")
			}
			if cmd.Flags().Changed("dns-resolvers") {
				s, _ := cmd.Flags().GetString("dns-resolvers")
				config.DNSServer.DNSResolvers = strings.Split(s, ",")
			}
			if cmd.Flags().Changed("max-connections") {
				config.DNSServer.MaxConnections, _ = cmd.Flags().GetInt("max-connections")
			}
			if cmd.Flags().Changed("verbose") {
				config.DNSServer.Verbose, _ = cmd.Flags().GetBool("verbose")
			}

			resolver := dohclient.NewResolver(dohclient.ResolverConfig{
				DoHServers:   config.DNSServer.DoHServers,
				DNSResolvers: config.DNSServer.DNSResolvers,
				Verbose:      config.DNSServer.Verbose,
				CacheTTL:     time.Duration(config.DNSServer.DoHResolveTTL) * time.Minute,
			})

			unblock := network.NewUnblockManager("")

			server := dnsserver.NewDNSServer(dnsserver.ServerConfig{
				Port:              config.DNSServer.Port,
				MaxConcurrentConn: config.DNSServer.MaxConnections,
				Verbose:           config.DNSServer.Verbose,
				CustomResolve:     config.DNSServer.CustomResolve,
			}, unblock, resolver)

			server.Run()

			return nil
		},
	}

	cmd.Flags().StringVar(&configFile, "config", "/opt/etc/vpner/vpner.yaml", "путь к YAML конфигурационному файлу")
	cmd.Flags().Int("port", 0, "порт (переопределение)")
	cmd.Flags().String("doh-servers", "", "DoH серверы через запятую")
	cmd.Flags().Int("doh-resolve-ttl", 0, "TTL резолва указанных doh серверов")
	cmd.Flags().String("dns-resolvers", "", "DNS резолверы через запятую")
	cmd.Flags().Int("max-connections", 0, "максимальное число подключений")
	cmd.Flags().Bool("verbose", false, "включить подробный лог")

	return cmd
}
