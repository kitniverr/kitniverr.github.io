package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"

import bcrypt "golang.org/x/crypto/bcrypt"

import "net/http"

var db *sql.DB
var err error

func signupPage(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(res, req, "signup.html")
		return
	}

	userid := req.FormValue("userid")
	password := req.FormValue("password")

	var user string

	err := db.QueryRow("SELECT userid FROM login WHERE userid=?", userid).Scan(&user)

	switch {
	case err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(res, "Error en el servidor, cuenta no fue creada.", 500)
			return
		}

		_, err = db.Exec("INSERT INTO login(userid, password) VALUES(?, ?)", userid, hashedPassword)
		if err != nil {
			http.Error(res, "Error en el servidor, cuenta no fue creada..", 500)
			return
		}

		res.Write([]byte("User created!"))
		return
	case err != nil:
		http.Error(res, "Error en el servidor, cuenta no fue creada.", 500)
		return
	default:
		http.Redirect(res, req, "/", 301)
	}
}

func loginPage(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.ServeFile(res, req, "login.html")
		return
	}

	userid := req.FormValue("userid")
	password := req.FormValue("password")

	var databaseUsername string
	var databasePassword string

	err := db.QueryRow("SELECT userid, password FROM login WHERE userid=?", userid).Scan(&databaseUsername, &databasePassword)

	if err != nil {
		http.Redirect(res, req, "/login", 301)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
	if err != nil {
		http.Redirect(res, req, "/login", 301)
		return
	}

	res.Write([]byte("Hola, haz ingresado" + databaseUsername))

}

func homePage(res http.ResponseWriter, req *http.Request) {
	http.ServeFile(res, req, "index.html")
}

func main() {
	db, err = sql.Open("mysql", "root:5840@tcp(192.168.1.12:3306)/covid")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	
	http.HandleFunc("/signup", signupPage)
	http.HandleFunc("/login", loginPage)
	http.HandleFunc("/", homePage)
	http.ListenAndServe(":8089", nil)
}
