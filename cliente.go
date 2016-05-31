// cliente
package main

import (
	"./util"
	/*"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"*/
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	/*"encoding/base64"*/
	"encoding/json"
	"fmt"
	/*"io"*/
	"bufio"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	/*"golang.org/x/crypto/scrypt"*/)

// mensaje de entrada de expresiones regulares (busque un comando /lo_que_sea )
var standardInputMessageRegex, _ = regexp.Compile(`^\/([^\s]*)\s*(.*)$`)

// comando de servidor chat /comando [username] contenido del cuerpo
var chatServerResponseRegex, _ = regexp.Compile(`^\/([^\s]*)\s?(?:\[([^\]]*)\])?\s*(.*)$`)

// estructura contenedor del comando
type Command struct {
	// "leave", "message", "enter"
	Command, Username, Body string
}

func main() {
	client()
}

// gestiona el modo cliente
func client() {
	fmt.Println("CHAT SEGURO")
	fmt.Println(" - Loguearte (1)")
	fmt.Println(" - Crear usuario (2)")
	fmt.Println(" - Salir (0)")
	fmt.Print("Selecciona una opcion: ")

	switch util.ReadInput() {
	case "1":
		if ok, username, password := Login(); ok {
			chat(username, password)
		} else {
			client()
		}

	case "2":
		NewUser()
		client()

	case "0":
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

func Login() (bool, string, string) {

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
	return response.Ok, username, password

}

//Esta funcion cierra el programa
func Salir() {
	fmt.Println("Hasta luego.")
}

func chat(username string, password string) {
	properties := util.LoadConfig()

	conn, err := net.Dial("tcp", properties.Hostname+":"+properties.Port)
	util.CheckForError(err, "Conexion rechazada")
	defer conn.Close()

	fmt.Print("Modo Chat..." + "\n")
	// escuchando al servidor y a la consola del usuario
	go watchForConnectionInput(username, password, properties, conn)
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
				sendCommand("message", message, conn)
			} else {
				switch command.Command {

				// entrar a una sala privada
				case "enter":
					sendCommand("enter", command.Body, conn)

				// ignorar a alguien
				case "ignore":
					sendCommand("ignore", command.Body, conn)

				// dejar la sala
				case "leave":
					// dejar la sala, no permite salas de salas
					sendCommand("leave", "", conn)

				// desconectar del servidor
				case "disconnect":
					sendCommand("disconnect", "", conn)
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
func watchForConnectionInput(username string, password string, properties util.Properties, conn net.Conn) {
	reader := bufio.NewReader(conn)

	for true {
		message, err := reader.ReadString('\n')
		util.CheckForError(err, "Perdida la conexión al servidor")
		message = strings.TrimSpace(message)
		if message != "" {
			Command := parseCommand(message)
			switch Command.Command {

			//listo
			case "ready":
				message := autTCP(username, password)
				sendCommand("user", message, conn)

			// conectado
			case "connect":
				fmt.Printf(properties.HasEnteredTheLobbyMessage+"\n", Command.Username)

			// desconectado
			case "disconnect":
				fmt.Printf(properties.HasLeftTheLobbyMessage+"\n", Command.Username)

			// ha entrado a...
			case "enter":
				fmt.Printf(properties.HasEnteredTheRoomMessage+"\n", Command.Username, Command.Body)

			// ha salido de...
			case "leave":
				fmt.Printf(properties.HasLeftTheRoomMessage+"\n", Command.Username, Command.Body)

			// el usuario ha enviado un mensaje
			case "message":
				if Command.Username != username {
					fmt.Printf(properties.ReceivedAMessage+"\n", Command.Username, Command.Body)
				}

			// ignorando
			case "ignoring":
				fmt.Printf(properties.IgnoringMessage+"\n", Command.Body)
			}
		}
	}
}

// send a command to the chat server
// commands are in the form of /command {command specific body content}\n
func sendCommand(command string, body string, conn net.Conn) {

	// hash con SHA512 del body
	bodyClient := sha512.Sum512([]byte(body))
	bodyEncode := bodyClient[:32] // una mitad para el login (256 bits)

	message := fmt.Sprintf("/%v %v\n", util.Encode(command), util.Encode(util.Encode64(bodyEncode))
	conn.Write([]byte(message))
}

// parse the input message and return an Command
// if there is a command the "Command" will != "", otherwise just Body will exist
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

// look for "/Command [name] body contents" where [name] is optional
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
		// it's irritating that I can't return a nil value here - must be something I'm missing
		return Command{}
	}
}

func autTCP(username string, password string) string {
	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)

	return username + ":::" + util.Encode64(keyLogin)
}
