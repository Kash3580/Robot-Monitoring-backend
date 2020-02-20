package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	socketio "github.com/googollee/go-socket.io"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/gin-gonic/gin"
)

type DataPoint struct {
	RemoteAdd string
	Points    string
}

type User struct {
	//ID       int    `json:"id"`

	FirstName string `json:"firstName"`

	LastName string `json:"lastName"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     int    `json:"role"`
}

type JWT struct {
	Token string `json:"token"`
}

func readPackets(s socketio.Conn, ser *net.UDPConn) {

	p := make([]byte, 1024)

	prevData := ""
	//	db := getSqlConnection()
	//	collection := getMongoDBConnection()
	for {
		n, remoteaddr, err := ser.ReadFromUDP(p)
		msg := strings.Split(string(p[:n]), ",")
		//fmt.Printf("Prev:  %s %s \n", prevData, msg[1])
		if prevData != msg[1] {
			fmt.Printf("Read a message from %v %s \n", remoteaddr, p[:n])
			prevData = msg[1]
			//insertValueToDB(collection, msg[1])
			//insertIntoMySQL(db, msg[1])
			s.Emit("field", string(p[:n]))

		}
		if err != nil {
			fmt.Printf("Client error  found :  %v\n", err)

			return
		}

	}
	//defer db.Close()
}

func insertValueToDB(collection *mongo.Collection, res string) {

	record := DataPoint{time.Now().Format("2006.01.02 15:04:05"), res}

	insertResult, err := collection.InsertOne(context.TODO(), record)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Inserted a single document: ", insertResult.InsertedID)

}

func insertIntoMySQL(db *sql.DB, res string) {

	fmt.Println(time.Now().Format("2006.01.02 15:04:05"))
	insert, err := db.Query("INSERT INTO DataPoint (recordDate,point)VALUES ('" + time.Now().Format("2006-01-02 15:04:05") + "', '" + res + "' )")

	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Record inserted into Mysql ")
	defer insert.Close()

}

func insertUserMySQL(db *sql.DB, user User) {

	fmt.Println(time.Now().Format("2006.01.02 15:04:05"))
	insert, err := db.Query("INSERT INTO user (firstname,lastname,email,password)VALUES ('" + user.FirstName + "', '" + user.LastName + "', '" + user.Email + "', '" + user.Password + "' )")

	if err != nil {
		panic(err.Error())
	}
	fmt.Println("User inserted into Mysql ")
	defer insert.Close()

}

func VerifyUserExist(db *sql.DB, user User) bool {

	fmt.Println(time.Now().Format("2006.01.02 15:04:05"))
	record, err := db.Query("Select firstname,lastname,email,password,role_id from user where   email='" + user.Email + "' and password='" + user.Password + "'")

	if err != nil {
		panic(err.Error())
		return false
	}

	dbuser := User{}
	for record.Next() {
		var roleid int
		var fname, lname, email, password string
		err = record.Scan(&fname, &lname, &email, &password, &roleid)
		if err != nil {
			panic(err.Error())
		}
		dbuser.FirstName = fname
		dbuser.LastName = lname
		dbuser.Email = email
		dbuser.Role = roleid
	}
	if dbuser.Email != "" {
		return true
	}

	defer record.Close()
	return false
}

func getSqlConnection() *sql.DB {
	db, err := sql.Open("mysql", "root:icl=12321@/test")

	if err != nil {
		log.Fatal(err)
		return nil
	}
	fmt.Println("Connected to MySQL!")
	return db
}

func getMongoDBConnection() *mongo.Collection {

	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")

	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)

	err = client.Ping(context.TODO(), nil)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	collection := client.Database("GoDB").Collection("datapoint")
	return collection
}

func getSocketConn() *net.UDPConn {
	addr := net.UDPAddr{
		Port: 41181,
		IP:   net.ParseIP("127.0.0.1"),
	}
	ser, err := net.ListenUDP("udp", &addr)

	if err != nil {
		log.Fatal(err)
	}
	return ser

}
func main() {

	server, err := socketio.NewServer(nil)
	if err != nil {
		fmt.Printf("Some error %v\n", err)
		return
	}
	ser := getSocketConn()
	server.OnConnect("/", func(s socketio.Conn) error {
		if s == nil {
			fmt.Println("No Connection found ")
		}

		s.SetContext("")

		fmt.Println("connected:", s.ID())
		readPackets(s, ser)

		return nil
	})
	server.OnEvent("/msg", "notice", func(s socketio.Conn, msg string) {
		fmt.Println("notice:", msg)

		fmt.Println("connected:", s.ID())

		//readPackets(s)

	})
	server.OnEvent("/user", "msg", func(s socketio.Conn, msg string) {
		fmt.Println("notice:", msg)
		fmt.Println("connected:", s.ID())
		//	readPackets(s)
	})

	server.OnError("/", func(s socketio.Conn, e error) {
		fmt.Println("meet error:", e)

	})
	server.OnDisconnect("/", func(s socketio.Conn, reason string) {
		fmt.Println("closed", reason)

	})
	go server.Serve()
	defer server.Close()

	go func() {
		router := gin.Default()
		router.POST("/signup", registerUser)
		router.POST("/user", userAuth)
		router.POST("/validatetoken", validateRequest)
		router.POST("/forgot-password", forgotPassword)
		router.POST("/newpassword", resetPassword)
		router.Run(":4001")
	}()

	http.Handle("/socket.io/", server)
	http.Handle("/", http.FileServer(http.Dir("./asset1")))
	log.Println("Serving at localhost:4000...")
	log.Fatal(http.ListenAndServe(":4000", nil))

	return
}
func registerUser(c *gin.Context) {
	db := getSqlConnection()
	var user User
	fmt.Println("registering user...")
	body := c.Request.Body
	x, _ := ioutil.ReadAll(body)
	//_ = json.NewDecoder(body).Decode(&user)
	err := json.Unmarshal(x, &user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Something went wrong",
		})
		return
	}
	if len(user.FirstName) == 0 && len(user.LastName) == 0 && len(user.Email) == 0 && len(user.Password) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Fields are empty",
		})
		return
	}

	insertUserMySQL(db, user)
	db.Close()

	c.JSON(http.StatusOK, gin.H{
		"message": "You have successfully registered. Thank you!!!",
	})
}
func userAuth(c *gin.Context) {
	var user User
	var token string
	db := getSqlConnection()

	fmt.Println("user auth called")

	body := c.Request.Body
	x, _ := ioutil.ReadAll(body)
	//_ = json.NewDecoder(body).Decode(&user)
	_ = json.Unmarshal(x, &user)
	fmt.Println(user.Email)

	isValid := VerifyUserExist(db, user)
	db.Close()

	if isValid {
		token, _ = GenerateToken(user)
	} else {
		token = "Not Found"
	}

	c.JSON(http.StatusOK, gin.H{
		"message": token,
	})

}
func forgotPassword(c *gin.Context) {
	var user User

	fmt.Println("forgot password called")

	body := c.Request.Body
	x, _ := ioutil.ReadAll(body)
	//_ = json.NewDecoder(body).Decode(&user)
	_ = json.Unmarshal(x, &user)
	fmt.Println(user.Email)
	token, _ := GenerateToken(user)

	c.JSON(http.StatusOK, gin.H{
		"message": "http://localhost:3000/reset-password/?id=" + token,
	})

}

func resetPassword(c *gin.Context) {
	var user User

	fmt.Println("reset password called")

	body := c.Request.Body
	x, _ := ioutil.ReadAll(body)
	//_ = json.NewDecoder(body).Decode(&user)
	_ = json.Unmarshal(x, &user)

	c.JSON(http.StatusOK, gin.H{
		"message": "Your password has been reset successfully",
	})

}

func validateRequest(c *gin.Context) {

	body := c.Request.Body
	x, _ := ioutil.ReadAll(body)
	fmt.Println(string(x))

	isValid, _ := ParseToken(string(x))
	fmt.Println("token value :", isValid)
	c.JSON(http.StatusOK, gin.H{
		"message": isValid,
	})

}

func ParseToken(mytoken string) (bool, error) {
	secret := "secret"
	token, err := jwt.Parse(mytoken, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err == nil && token.Valid {
		//	fmt.Println("Your token is valid.  I like your style.")
		return true, nil

	} else {
		//	fmt.Println("This token is terrible!  I cannot accept this.")
		return false, nil
	}
}

func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}
