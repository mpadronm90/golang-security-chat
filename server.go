// server
package main

import (
	"./util"
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

const LOBBY = "lobby"

// mapa con todos los usuarios
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
		/*util.ExisteUsuario(u.Name) // ¿existe ya el usuario?*/
		if ok {
			util.Response(w, false, "Usuario ya registrado")
		} else {
			u.Key = password
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
	// Inicia el servidor de chat
	properties := util.LoadConfig()
	psock, err := net.Listen("tcp", ":"+properties.Port)
	util.CheckForError(err, "Imposible crear el servidor")

	// Módulo de autenticación
	go server_tls()

	for {
		// conexiones aceptadas
		conn, err := psock.Accept()
		util.CheckForError(err, "No se aceptan conexiones")

		// llevar un registro de los datos de cliente
		client := util.Client{Connection: conn, Room: LOBBY, Properties: properties}
		client.Register()

		// manejo de las peticiones del cliente de forma no bloqueante
		channel := make(chan string)
		go waitForInput(channel, &client)
		go handleInput(channel, &client, properties)

		util.SendClientMessage("listo", properties.Port, &client, true, properties, gUsers)
	}
}

// esperar a la entrada del usuario y la señal del canal
func waitForInput(out chan string, client *util.Client) {
	defer close(out)

	reader := bufio.NewReader(client.Connection)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			// conexion cerrada, quitar al usuario de la lista de chateadores
			client.Close(true, gUsers)
			return
		}
		out <- string(line)
	}
}

// escuchar las actualizaciones de canal para un cliente y manejar el mensaje
// los mensajes deben estar en el formato de / { acción } {contenido} donde el contenido es opcional dependiendo de la acción
// las acciones respaldadas son "user ", " chat", y "quit". el "user " debe autenticarse antes de que los mensajes de chat esten permitidos
func handleInput(in <-chan string, client *util.Client, props util.Properties) {

	for {
		message := <-in

		if message != "" {

			message = strings.TrimSpace(message)
			action, body := getAction(message, client.Username)

			if action != "" {

				switch action {

				// El ususario envia un mensaje
				case "mensaje":
					util.SendClientMessage("mensaje", body, client, false, props, gUsers)

				// El usuario provee el nombre de usuario desde despues de la autenticación en tls
				case "user":
					client.Username = body
					util.SendClientMessage("conectado", "conectado", client, false, props, gUsers)

				// El usuario se desconecta
				case "desconectar":
					client.Close(false, gUsers)

				// El usuario ignora a a otro
				case "ignorar":
					client.Ignore(body)
					util.SendClientMessage("ignorando", body, client, false, props, gUsers)

				// El usuario entra a una sala privada
				case "entrar":
					if body != "" {
						client.Room = body
						util.SendClientMessage("entra", body, client, false, props, gUsers)
					}

				// El usuario deja la sala
				case "dejar":
					if client.Room != LOBBY {
						util.SendClientMessage("deja", client.Room, client, false, props, gUsers)
						client.Room = LOBBY
					}

				default:
					util.SendClientMessage("noreconocido", action, client, true, props, gUsers)
				}
			}
		}
	}
}

// analizar el contenido del mensaje ( / { acción } { mensaje desencriptado} ) y devolver los valores individuales
func getAction(message, user string) (string, string) {
	actionRegex, _ := regexp.Compile(`^\/([^\s]*)\s*(.*)$`)
	res := actionRegex.FindAllStringSubmatch(message, -1)

	if len(res) == 1 {
		if len(user) != 0 {
			return res[0][1], string(util.Decrypt(util.Decode64(res[0][2]), gUsers[user].Key))
		} else {
			return res[0][1], string(util.Decode64(res[0][2]))
		}
	}
	return "", ""
}

// Verificar pass
func verifyUser(body string) (bool, string) {

	i := strings.Index(body, ":::")
	username := body[:i]

	pass := util.Decode64(body[i+3 : len(body)])

	u, ok := gUsers[username] // ¿existe ya el usuario?
	if !ok {
		return false, ""
	}

	hash, _ := scrypt.Key(pass, u.Salt, 16384, 8, 1, 32) // scrypt(contraseña)
	if bytes.Compare(u.Hash, hash) != 0 {                // comparamos
		return false, ""
	}

	return true, username
}
