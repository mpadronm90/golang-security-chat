// server
package main

import (
	"./util"
	"bytes"
	/*"compress/zlib"
	"crypto/aes"
	"crypto/cipher"*/
	"crypto/rand"
	/*"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"*/
	/*"encoding/json"*/
	"fmt"
	/*"io"*/
	"net/http"
	/*"net/url"*/
	/*"os"*/
	/*"./endpoint/auth"*/
	"./endpoint/json"
	"bufio"
	"net"
	"regexp"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const LOBBY = "lobby"

// mapa con todos los usuarios
// (se podría codificar en JSON y escribir/leer de disco para persistencia)
var gUsers map[string]util.User

// gestiona el modo servidor
func main() {
	server_chat()
}

func server_tls() {
	properties := util.LoadConfig()
	gUsers = make(map[string]util.User) // inicializamos mapa de usuarios
	fmt.Println("Server ::  TLS/HTTP :: Security Chat :: Port " + properties.ServerTlsPort)

	http.HandleFunc("/", handler) // asignamos un handler global
	// escuchamos el puerto 10443 con https y comprobamos el error
	util.Chk(http.ListenAndServeTLS(":"+properties.ServerTlsPort, "cert.pem", "key.pem", nil))

}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		u := util.User{}
		u.Name = req.Form.Get("user")                   // nombre
		u.Salt = make([]byte, 16)                       // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                               // la sal es aleatoria
		u.Data = make(map[string]string)                // reservamos mapa de datos de usuario
		u.Data["private"] = req.Form.Get("prikey")      // clave privada
		u.Data["public"] = req.Form.Get("pubkey")       // clave pública
		password := util.Decode64(req.Form.Get("pass")) // contraseña (keyLogin)

		// "hasheamos" la contraseña con scrypt
		u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)

		_, ok := gUsers[u.Name] // ¿existe ya el usuario?
		if ok {
			util.Response(w, false, "Usuario ya registrado")
		} else {
			gUsers[u.Name] = u
			util.Response(w, true, "Usuario registrado")
		}

	case "login": // ** login
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			util.Response(w, false, "Usuario inexistente")
			return
		}

		password := util.Decode64(req.Form.Get("pass"))          // obtenemos la contraseña
		hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32) // scrypt(contraseña)
		if bytes.Compare(u.Hash, hash) != 0 {                    // comparamos
			util.Response(w, false, "Credenciales inválidas")
			return
		}
		util.Response(w, true, "Credenciales válidas")

	default:
		util.Response(w, false, "Comando inválido")
	}

}

func server_chat() {
	// start the chat server
	properties := util.LoadConfig()
	psock, err := net.Listen("tcp", ":"+properties.Port)
	util.CheckForError(err, "Can't create server")

	fmt.Printf("Chat server started on port %v...\n", properties.Port)
	go server_tls()

	// start the JSON endpoing server
	go json.Start()

	for {
		fmt.Print("Entra aqui" + "\n")
		// accept connections
		conn, err := psock.Accept()
		util.CheckForError(err, "Can't accept connections")

		// keep track of the client details
		client := util.Client{Connection: conn, Room: LOBBY, Properties: properties}
		client.Register()

		// allow non-blocking client request handling
		channel := make(chan string)
		go waitForInput(channel, &client)
		go handleInput(channel, &client, properties)

		util.SendClientMessage("ready", properties.Port, &client, true, properties)
	}
}

// wait for client input (buffered by newlines) and signal the channel
func waitForInput(out chan string, client *util.Client) {
	defer close(out)

	reader := bufio.NewReader(client.Connection)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			// connection has been closed, remove the client
			client.Close(true)
			return
		}
		out <- string(line)
	}
}

// listen for channel updates for a client and handle the message
// messages must be in the format of /{action} {content} where content is optional depending on the action
// supported actions are "user", "chat", and "quit".  the "user" must be set before any chat messages are allowed
func handleInput(in <-chan string, client *util.Client, props util.Properties) {

	for {
		message := <-in
		if message != "" {
			message = strings.TrimSpace(message)
			action, body := getAction(message)

			if action != "" {
				switch action {

				// the user has submitted a message
				case "message":
					util.SendClientMessage("message", body, client, false, props)

				// the user has provided their username (initialization handshake)
				case "user":
					client.Username = body
					util.SendClientMessage("connect", "", client, false, props)

				// the user is disconnecting
				case "disconnect":
					client.Close(false)

				// the user is disconnecting
				case "ignore":
					client.Ignore(body)
					util.SendClientMessage("ignoring", body, client, false, props)

				// the user is entering a room
				case "enter":
					if body != "" {
						client.Room = body
						util.SendClientMessage("enter", body, client, false, props)
					}

				// the user is leaving the current room
				case "leave":
					if client.Room != LOBBY {
						util.SendClientMessage("leave", client.Room, client, false, props)
						client.Room = LOBBY
					}

				default:
					util.SendClientMessage("unrecognized", action, client, true, props)
				}
			}
		}
	}
}

// parse out message contents (/{action} {message}) and return individual values
func getAction(message string) (string, string) {
	actionRegex, _ := regexp.Compile(`^\/([^\s]*)\s*(.*)$`)
	res := actionRegex.FindAllStringSubmatch(message, -1)
	if len(res) == 1 {
		return res[0][1], res[0][2]
	}
	return "", ""
}
