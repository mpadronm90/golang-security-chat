package util

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	//"gopkg.in/mgo.v2"
	//"gopkg.in/mgo.v2/bson"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// time format for log files and JSON response
const TIME_LAYOUT = "Jan 2 2006 15.04.05 -0700 MST"

// thins we are encoding when sending stuff over the wire to clients
var ENCODING_UNENCODED_TOKENS = []string{"%", ":", "[", "]", ",", "\""}
var ENCODING_ENCODED_TOKENS = []string{"%25", "%3A", "%5B", "%5D", "%2C", "%22"}
var DECODING_UNENCODED_TOKENS = []string{":", "[", "]", ",", "\"", "%"}
var DECODING_ENCODED_TOKENS = []string{"%3A", "%5B", "%5D", "%2C", "%22", "%25"}

// Container for client username and connection details
type Client struct {
	// the client's connection
	Connection net.Conn
	// the client's username
	Username string
	// the current room or "global"
	Room string
	// list of usernames we are ignoring
	ignoring []string
	// the config properties
	Properties Properties
}

// Close the client connection and clenup
func (client *Client) Close(doSendMessage bool) {
	if doSendMessage {
		// if we send the close command, the connection will terminate causing another close
		// which will send the message
		SendClientMessage("disconnect", "", client, false, client.Properties)
	}
	client.Connection.Close()
	clients = removeEntry(client, clients)
}

// Register the connection and cache it
func (client *Client) Register() {
	clients = append(clients, client)
}

func (client *Client) Ignore(username string) {
	client.ignoring = append(client.ignoring, username)
}

func (client *Client) IsIgnoring(username string) bool {
	for _, value := range client.ignoring {
		if value == username {
			return true
		}
	}
	return false
}

// log content container
type Action struct {
	// "message", "leave", "enter", "connect", "disconnect"
	Command string `json:"command"`
	// action specific content - either the chat message or room that was entered/left
	Content string `json:"content"`
	// the username that performed the action
	Username string `json:"username"`
	// ip address of the uwer
	IP string `json:"ip"`
	// timestamp of the activity
	Timestamp string `json:"timestamp"`
}

// general configuration properties
type Properties struct {
	// chat server hostname (for client connection)
	Hostname string
	// chat server port (for server execution and client connection)
	Port string
	// port used for JSON server
	JSONEndpointPort string
	// Server TLS port
	ServerTlsPort string
	// message format for when someone enters a private room
	HasEnteredTheRoomMessage string
	// message format for when someone leaves a private room
	HasLeftTheRoomMessage string
	// message format for when someone connects
	HasEnteredTheLobbyMessage string
	// message format for when someone disconnects
	HasLeftTheLobbyMessage string
	// message format for when someone sends a chat
	ReceivedAMessage string
	// message received when the user is ignoring someone else
	IgnoringMessage string
	// the absolute log file location
	LogFile string
}

var actions = []Action{}

// cached config properties
var config = Properties{}

// static client list
var clients []*Client

// load the configuration properties from the "config.json" file
func LoadConfig() Properties {
	if config.Port != "" {
		return config
	}
	pwd, _ := os.Getwd()

	payload, err := ioutil.ReadFile(pwd + "/config.json")
	CheckForError(err, "No se puede leer el fichero json")

	var dat map[string]interface{}
	err = json.Unmarshal(payload, &dat)
	CheckForError(err, "Invalid JSON in config file")

	// probably a better way to unmarshall directly in the Properties struct but I haven't found it
	var rtn = Properties{
		Hostname:                  dat["Hostname"].(string),
		Port:                      dat["Port"].(string),
		JSONEndpointPort:          dat["JSONEndpointPort"].(string),
		ServerTlsPort:             dat["ServerTlsPort"].(string),
		HasEnteredTheRoomMessage:  dat["HasEnteredTheRoomMessage"].(string),
		HasLeftTheRoomMessage:     dat["HasLeftTheRoomMessage"].(string),
		HasEnteredTheLobbyMessage: dat["HasEnteredTheLobbyMessage"].(string),
		HasLeftTheLobbyMessage:    dat["HasLeftTheLobbyMessage"].(string),
		ReceivedAMessage:          dat["ReceivedAMessage"].(string),
		IgnoringMessage:           dat["IgnoringMessage"].(string),
		LogFile:                   dat["LogFile"].(string),
	}
	config = rtn
	return rtn
}

// remove client entry from stored clients
func removeEntry(client *Client, arr []*Client) []*Client {
	rtn := arr
	index := -1
	for i, value := range arr {
		if value == client {
			index = i
			break
		}
	}

	if index >= 0 {
		// we have a match, create a new array without the match
		rtn = make([]*Client, len(arr)-1)
		copy(rtn, arr[:index])
		copy(rtn[index:], arr[index+1:])
	}

	return rtn
}

// sent a message to all clients (except the sender)
func SendClientMessage(messageType string, message string, client *Client, thisClientOnly bool, props Properties) {

	if thisClientOnly {
		// this message is only for the provided client
		message = fmt.Sprintf("/%v", messageType)
		fmt.Fprintln(client.Connection, message)

	} else if client.Username != "" {
		// this message is for all but the provided client
		LogAction(messageType, message, client, props)

		// construct the payload to be sent to clients
		payload := fmt.Sprintf("/%v [%v] %v", messageType, client.Username, message)

		for _, _client := range clients {
			// write the message to the client
			if (thisClientOnly && _client.Username == client.Username) ||
				(!thisClientOnly && _client.Username != "") {

				// you should only see a message if you are in the same room
				if messageType == "mensaje" && client.Room != _client.Room || _client.IsIgnoring(client.Username) {
					continue
				}

				// you won't hear any activity if you are anonymous unless thisClientOnly
				// when current client will *only* be messaged
				// TODO encode/decode
				fmt.Fprintln(_client.Connection, payload)
			}
		}
	}
}

// fail if an error is provided and print out the message
func CheckForError(err error, message string) {
	if err != nil {
		println(message+": ", err.Error())
		os.Exit(1)
	}
}

// double quote the single quotes
func EncodeCSV(value string) string {
	return strings.Replace(value, "\"", "\"\"", -1)
}

// simple http-ish encoding to handle special characters
func Encode(value string) string {
	return replace(ENCODING_UNENCODED_TOKENS, ENCODING_ENCODED_TOKENS, value)
}

// simple http-ish decoding to handle special characters
func Decode(value string) string {
	return replace(DECODING_ENCODED_TOKENS, DECODING_UNENCODED_TOKENS, value)
}

// replace the from tokens to the to tokens (both arrays must be the same length)
func replace(fromTokens []string, toTokens []string, value string) string {
	for i := 0; i < len(fromTokens); i++ {
		value = strings.Replace(value, fromTokens[i], toTokens[i], -1)
	}
	return value
}

func LogAction(action string, message string, client *Client, props Properties) {
	ip := client.Connection.RemoteAddr().String()
	timestamp := time.Now().Format(TIME_LAYOUT)

	// keep track of the actions to query against for the JSON endpoing
	actions = append(actions, Action{
		Command:   action,
		Content:   message,
		Username:  client.Username,
		IP:        ip,
		Timestamp: timestamp,
	})

	if props.LogFile != "" {
		if message == "" {
			message = "N/A"
		}
		fmt.Printf("logging values %s, %s, %s\n", action, message, client.Username)

		logMessage := fmt.Sprintf("\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"\n",
			EncodeCSV(client.Username), EncodeCSV(action), EncodeCSV(message),
			EncodeCSV(timestamp), EncodeCSV(ip))

		f, err := os.OpenFile(props.LogFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			// try to create it
			err = ioutil.WriteFile(props.LogFile, []byte{}, 0600)
			f, err = os.OpenFile(props.LogFile, os.O_APPEND|os.O_WRONLY, 0600)
			CheckForError(err, "Cant create log file")
		}

		defer f.Close()
		_, err = f.WriteString(logMessage)
		CheckForError(err, "Can't write to log file")
	}
}

func QueryMessages(actionType string, search string, username string) []Action {

	isMatch := func(action Action) bool {
		if actionType != "" && action.Command != actionType {
			return false
		}
		if search != "" && !strings.Contains(action.Content, search) {
			return false
		}
		if username != "" && action.Username != username {
			return false
		}
		return true
	}

	rtn := make([]Action, 0, len(actions))

	// find out which items match the search criteria and add them to what we will be returning
	for _, value := range actions {
		if isMatch(value) {
			rtn = append(rtn, value)
		}
	}

	return rtn
}

// Security

// respuesta del servidor
type Resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

// ejemplo de tipo para un usuario
type User struct {
	Name string            // nombre de usuario
	Hash []byte            // hash de la contraseña
	Salt []byte            // sal para la contraseña
	Data map[string]string // datos adicionales del usuario
}

// función para comprobar errores (ahorra escritura)
func Chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func Encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	Chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para descifrar (con AES en este caso)
func Decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	Chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// función para comprimir
func Compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func Decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	Chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

// función para codificar de []bytes a string (Base64)
func Encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func Decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	Chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para escribir una respuesta del servidor
func Response(w io.Writer, ok bool, msg string) {
	r := Resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	Chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

// Función que lee la entrada de pantalla
func ReadInput() string {
	reader := bufio.NewReader(os.Stdin)
	os, err := reader.ReadString('\n')
	Chk(err)
	return string(TrimSuffix(os, "\n"))
}

// Función auxuliar que elimina el salto de linea de un string
func TrimSuffix(s, suffix string) string {
	if strings.HasSuffix(s, suffix) {
		s = s[:len(s)-len(suffix)]
	}
	return s
}

const (
	sttyArg0   = "/bin/stty"
	exec_cwdir = ""
)

// Tells the terminal to turn echo off.
var sttyArgvEOff []string = []string{"stty", "-echo"}

// Tells the terminal to turn echo on.
var sttyArgvEOn []string = []string{"stty", "echo"}

var ws syscall.WaitStatus = 0

// GetPass gets input hidden from the terminal from a user.
// This is accomplished by turning off terminal echo,
// reading input from the user and finally turning on terminal echo.
// prompt is a string to display before the user's input.
func GetPass(prompt string) (passwd string, err error) {
	sig := make(chan os.Signal, 10)
	brk := make(chan bool)

	// Display the prompt.
	fmt.Print(prompt)

	// File descriptors for stdin, stdout, and stderr.
	fd := []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()}

	// Setup notifications of termination signals to channel sig, create a process to
	// watch for these signals so we can turn back on echo if need be.
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGKILL, syscall.SIGQUIT,
		syscall.SIGTERM)
	go catchSignal(fd, sig, brk)

	// Turn off the terminal echo.
	pid, err := echoOff(fd)
	if err != nil {
		return "", err
	}

	// Turn on the terminal echo and stop listening for signals.
	defer close(brk)
	defer echoOn(fd)

	rd := bufio.NewReader(os.Stdin)
	syscall.Wait4(pid, &ws, 0, nil)

	line, err := rd.ReadString('\n')
	if err == nil {
		passwd = strings.TrimSpace(line)
	} else {
		err = fmt.Errorf("failed during password entry: %s", err)
	}

	// Carraige return after the user input.
	fmt.Println("")

	return passwd, err
}

// catchSignal tries to catch SIGKILL, SIGQUIT and SIGINT so that we can turn terminal
// echo back on before the program ends.  Otherwise the user is left with echo off on
// their terminal.
func catchSignal(fd []uintptr, sig chan os.Signal, brk chan bool) {
	select {
	case <-sig:
		echoOn(fd)
		os.Exit(-1)
	case <-brk:
	}
}

func echoOff(fd []uintptr) (int, error) {
	pid, err := syscall.ForkExec(sttyArg0, sttyArgvEOff, &syscall.ProcAttr{Dir: exec_cwdir, Files: fd})
	if err != nil {
		return 0, fmt.Errorf("failed turning off console echo for password entry:\n\t%s", err)
	}
	return pid, nil
}

// echoOn turns back on the terminal echo.
func echoOn(fd []uintptr) {
	// Turn on the terminal echo.
	pid, e := syscall.ForkExec(sttyArg0, sttyArgvEOn, &syscall.ProcAttr{Dir: exec_cwdir, Files: fd})
	if e == nil {
		syscall.Wait4(pid, &ws, 0, nil)
	}
}

func DecodeResponse(payload *http.Response) Resp {
	var dat Resp
	body, _ := ioutil.ReadAll(payload.Body)
	err := json.Unmarshal(body, &dat)
	CheckForError(err, "Invalid JSON in Server Response")
	return dat
}

func PostForm(client *http.Client, data url.Values) *http.Response {
	properties := LoadConfig()
	r, err := client.PostForm("https://localhost:"+properties.ServerTlsPort, data)
	Chk(err)
	return r
}

/*
func CrearUsuario(user User) bool {
	session, err := mgo.Dial("localhost")
	Chk(err)

	defer session.Close()

	session.SetMode(mgo.Monotonic, true)
	c := session.DB("chat").C("users")

	err = c.Insert(user)
	Chk(err)

	return true
}

func ExisteUsuario(username string) User {
	session, err := mgo.Dial("localhost")
	Chk(err)

	defer session.Close()

	session.SetMode(mgo.Monotonic, true)
	c := session.DB("chat").C("users")

	result := User{}
	err = c.Find(bson.M{"Name": username}).One(&result)
	Chk(err)

	println(result.Name)

	return result
}

*/
