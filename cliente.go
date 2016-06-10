// cliente
package main

import (
	"./util"
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// mensaje de entrada de expresiones regulares (busque un comando /lo_que_sea )
var standardInputMessageRegex, _ = regexp.Compile(`^\/([^\s]*)\s*(.*)$`)

// comando de servidor chat /comando [username] contenido del cuerpo
var chatServerResponseRegex, _ = regexp.Compile(`^\/([^\s]*)\s?(?:\[([^\]]*)\])?\s*(.*)$`)

// estructura contenedor del comando
type Command struct {
	// "leave", "message", "enter"
	Command, Username, Body string
}

var user util.User

func main() {
	client()
}

// gestiona el modo cliente
func client() {
	fmt.Println("-------------------------------------")
	fmt.Println("         GOCHA - CHAT SEGURO         ")
	fmt.Println("-----   ---------------------   -----")
	fmt.Println("                                     ")
	fmt.Println(" 1 - ENTRAR AL LOBBY                 ")
	fmt.Println(" 2 - NUEVO USUARIO                   ")
	fmt.Println(" 3 - SALIR                           ")
	fmt.Println("                                     ")
	fmt.Print("   Seleccione una opcion:              ")
	fmt.Print("                                       ")

	switch util.ReadInput() {
	case "1":
		if ok, username := Login(); ok {
			chat(username)
		} else {
			client()
		}

	case "2":
		NewUser()
		client()

	case "3":
		Salir()

	default:
		fmt.Println("Opción no válida")
		client()
	}
}

//esta funcion nos permite crear usuarios nuevos
func NewUser() {

	fmt.Println("Para crear un usuario nuevo necesitamos algunos datos...")

	// Guardamos el nombre del usuario
	fmt.Print("Usuario: ")
	Name := util.ReadInput()

	// Guardamos el password del usuario
	fmt.Print("Password: ")
	pass := util.ReadInput()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(pass))
	keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
	keyData := keyClient[32:64] // la otra para los datos (256 bits)

	// generamos un par de claves (privada, pública) para el servidor
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	util.Chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	util.Chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	util.Chk(err)

	//Registro
	data := url.Values{}                      // estructura para contener los valores
	data.Set("cmd", "register")               // comando (string)
	data.Set("user", Name)                    // usuario (string)
	data.Set("pass", util.Encode64(keyLogin)) // "contraseña" a base64

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", util.Encode64(util.Compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", util.Encode64(util.Encrypt(util.Compress(pkJSON), keyData)))

	r := util.PostForm(client, data)
	response := util.DecodeResponse(r)
	defer r.Body.Close()

	fmt.Println(response.Msg)
}

func Login() (bool, string) {

	fmt.Println("Introduce tu usuario y tu contraseña")

	fmt.Print("Usuario: ")
	username := util.ReadInput()
	password, err := util.GetPass("Password: ")
	util.Chk(err)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)

	data := url.Values{}
	data.Set("cmd", "login")                  // comando (string)
	data.Set("user", username)                // usuario (string)
	data.Set("pass", util.Encode64(keyLogin)) // contraseña (a base64 porque es []byte)

	r := util.PostForm(client, data)
	response := util.DecodeResponse(r)
	defer r.Body.Close()

	fmt.Println(response.Msg)
	if response.Ok == true {
		user.Name = username
		user.Key = keyLogin
	}
	return response.Ok, username

}

//Esta funcion cierra el programa
func Salir() {
	fmt.Println("Hasta luego.")
}

func chat(username string) {

	properties := util.LoadConfig()

	conn, err := net.Dial("tcp", properties.Hostname+":"+properties.Port)
	util.CheckForError(err, "Conexion rechazada")
	defer conn.Close()

	fmt.Print("Modo Chat..." + "\n")
	// escuchando al servidor y a la consola del usuario
	go watchForConnectionInput(username, properties, conn)
	for true {
		watchForConsoleInput(conn)
	}

}

// continua escuchando la consola del usuario
// envia un mensaje al servidor cuando recibe una peticion
func watchForConsoleInput(conn net.Conn) {
	reader := bufio.NewReader(os.Stdin)

	for true {
		message, err := reader.ReadString('\n')
		util.CheckForError(err, "Perdida la conexion")

		message = strings.TrimSpace(message)
		if message != "" {
			command := parseInput(message)

			if command.Command == "" {
				// un simple mensaje
				sendCommand("mensaje", message, conn)
			} else {
				switch command.Command {

				// entrar a una sala privada
				case "entrar":
					sendCommand("entrar", command.Body, conn)

				// ignorar a alguien
				case "ignorar":
					sendCommand("ignorar", command.Body, conn)

				// dejar la sala
				case "dejar":
					// dejar la sala, no permite salas de salas
					sendCommand("dejar", "", conn)

				// desconectar del servidor
				case "desconectar":
					sendCommand("desconectar", "", conn)
					client()

				default:
					fmt.Printf("comando desconocido \"%s\"\n", command.Command)
				}
			}
		}
	}
}

// escuchar los comandos que vienen desde el servidor de chat
// ej: alguien ha entrado, alguien ha salido, alguien ha enviado un mensaje
func watchForConnectionInput(username string, properties util.Properties, conn net.Conn) {
	reader := bufio.NewReader(conn)

	for true {
		message, err := reader.ReadString('\n')
		util.CheckForError(err, "Perdida la conexión al servidor")
		message = strings.TrimSpace(message)
		if message != "" {
			Command := parseCommand(message)
			switch Command.Command {

			//listo
			case "listo":
				//message := autTCP(username, password)
				sendCommand("user", username, conn)

			// conectado
			case "conectado":
				fmt.Printf(properties.HasEnteredTheLobbyMessage+"\n", Command.Username)

			// desconectado
			case "desconectado":
				fmt.Printf(properties.HasLeftTheLobbyMessage+"\n", Command.Username)

			// ha entrado a...
			case "entra":
				fmt.Printf(properties.HasEnteredTheRoomMessage+"\n", Command.Username, Command.Body)

			// ha salido de...
			case "deja":
				fmt.Printf(properties.HasLeftTheRoomMessage+"\n", Command.Username, Command.Body)

			// el usuario ha enviado un mensaje
			case "mensaje":
				if Command.Username != username {
					fmt.Printf(properties.ReceivedAMessage+"\n", Command.Username, Command.Body)
				}

			// ignorando
			case "ignorando":
				fmt.Printf(properties.IgnoringMessage+"\n", Command.Body)
			}
		}
	}
}

func sendCommand(command string, body string, conn net.Conn) {

	if command != "user" {
		// Procedemos a encriptar el mensaje
		encriptado := util.Encrypt([]byte(body), user.Key)
		message := fmt.Sprintf("/%v %v\n", util.Encode(command), util.Encode(util.Encode64(encriptado)))
		conn.Write([]byte(message))
	} else {
		message := fmt.Sprintf("/%v %v\n", util.Encode(command), util.Encode(util.Encode64([]byte(body))))
		conn.Write([]byte(message))
	}

}

func parseInput(message string) Command {
	res := standardInputMessageRegex.FindAllStringSubmatch(message, -1)
	if len(res) == 1 {
		// there is a command
		return Command{
			Command: res[0][1],
			Body:    res[0][2],
		}
	} else {
		return Command{
			Body: util.Decode(message),
		}
	}
}

func parseCommand(message string) Command {
	res := chatServerResponseRegex.FindAllStringSubmatch(message, -1)

	if len(res) == 1 {
		// we've got a match
		return Command{
			Command:  util.Decode(res[0][1]),
			Username: util.Decode(res[0][2]),
			Body:     util.Decode(res[0][3]),
		}
	} else {

		return Command{}
	}
}

/*
func autTCP(username string, password string) string {
	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)

	return username + ":::" + util.Encode64(keyLogin)
}
*/
