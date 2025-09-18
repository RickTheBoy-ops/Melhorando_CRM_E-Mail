package main

import (
	"os"
	"fmt"
)

func main() {
	// Verifica se foi passado algum argumento
	if len(os.Args) < 2 {
		fmt.Println("Uso: go run main.go [command]")
		fmt.Println("Comandos disponíveis:")
		fmt.Println("  app         - Executar a aplicação principal")
		fmt.Println("  create      - Criar admin")
		fmt.Println("  check       - Verificar admin")
		fmt.Println("  init-db     - Inicializar banco de dados SQLite")
		fmt.Println("  dev         - Executar em modo desenvolvimento")
		return
	}

	command := os.Args[1]

	switch command {
	case "app":
		mainApp()
	case "create":
		createAdminMain()
	case "check":
		checkAdminMain()
	case "init-db":
		initSQLiteMain()
	case "dev":
		runDevMain()
	default:
		fmt.Printf("Comando desconhecido: %s\n", command)
		fmt.Println("Use 'go run main.go' para ver os comandos disponíveis")
	}
}
