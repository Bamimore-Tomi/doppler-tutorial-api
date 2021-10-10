package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var db *sql.DB

type User struct {
	Id        int
	Username  string `form:"username" json:"username" binding:"required"`
	Email     string `form:"email" json:"email" binding:"required"`
	Password  string `form:"password" json:"password" binding:"required"`
	Firstname string `form:"firstname" json:"firstname"`
	Lastname  string `form:"lastname" json:"lastname"`
}

type LoginUser struct {
	Email    string `form:"email" json:"email" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

type AuthedUser struct {
	ID    int
	Email string
}

type Token struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type Todo struct {
	Id          int
	Title       string `form:"title" json:"title" binding:"required"`
	Description string `form:"description" json:"description" binding:"required"`
	Deadline    time.Time
}

type TodoResponse struct {
	Title       string
	Description string
	Deadline    time.Time
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqAuth := c.Request.Header.Get("Authorization")
		if reqAuth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization access failure1"})
			return
		}
		splitReqAuth := strings.Split(reqAuth, "Bearer ")
		if len(splitReqAuth) < 2 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization access failure2"})
			return
		}
		reqToken := splitReqAuth[1]
		var secret = []byte(os.Getenv("SECRET_KEY"))
		token, err := jwt.Parse(reqToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secret, nil
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			queryUser, err := db.Query("SELECT pk, email FROM users WHERE email=?", claims["email"])
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			if queryUser.Next() {
				var authed AuthedUser
				err := queryUser.Scan(&authed.ID, &authed.Email)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				c.Set("user", authed)
				c.Next()
			} else {
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "user not found"})
				return
			}
		}

	}
}

func ConnDb() *sql.DB {
	godotenv.Load()
	username := os.Getenv("DB_USERNAME")
	password := os.Getenv("DB_PASSWORD")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	schema := os.Getenv("DB_NAME")
	fmt.Println(fmt.Sprintf("DB_USERNAME: %s\nDB_PASSWORD: %s\nDB_HOST: %s\nDB_PORT: %s\nDB_NAME: %s", username, password, host, port, schema))
	db_string := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", username, password, host, port, schema)
	db, err := sql.Open("mysql", db_string)
	if err != nil {
		log.Fatalln(err)
	}
	return db
}

func GenerateJwt(email string) (string, error) {
	secret := []byte(os.Getenv("SECRET_KEY"))
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["email"] = email
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func Register(c *gin.Context) {
	var newUser User
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := db.Query("SELECT email FROM users WHERE email = ?", newUser.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	if res.Next() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email already exists"})
		return
	}
	passwordHash, err := GeneratePasswordHash(newUser.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	query := "INSERT INTO users (email,firstname,lastname,username,password) VALUES (?,?,?,?,?)"
	ins, err := db.Exec(query, newUser.Email, newUser.Firstname, newUser.Lastname, newUser.Username, passwordHash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	lastInserted, err := ins.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	c.JSON(http.StatusOK, gin.H{"id": lastInserted})
}

func GeneratePasswordHash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
func Login(c *gin.Context) {
	var user LoginUser
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := db.Query("SELECT password FROM users WHERE email = ?", user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !res.Next() {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
	} else {
		var password string
		err := res.Scan(&password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		} else if !CheckPassword(user.Password, password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid login credentials"})
			return
		}
	}
	newToken, err := GenerateJwt(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	var token Token
	token.Email = user.Email
	token.Token = newToken

	c.JSON(http.StatusOK, token)

}

func CreateTodo(c *gin.Context) {
	curUser := c.MustGet("user").(AuthedUser)
	var todo Todo
	err := c.ShouldBindJSON(&todo)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Println(todo)
	query := "INSERT INTO todos (user_id, title, description, deadline) VALUES (?,?, ?, ?)"
	ins, err := db.Exec(query, curUser.ID, todo.Title, todo.Description, todo.Deadline)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
	lastInserted, err := ins.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	c.JSON(http.StatusOK, gin.H{"id": lastInserted})

}

func ListTodo(c *gin.Context) {
	curUser := c.MustGet("user").(AuthedUser)
	var todos []TodoResponse
	query := "SELECT title, description, deadline FROM todos WHERE user_id = ?"
	res, err := db.Query(query, curUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	for res.Next() {
		var todo TodoResponse
		err = res.Scan(&todo.Title, &todo.Description, &todo.Deadline)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		fmt.Println(todo)
		todos = append(todos, todo)
	}
	c.JSON(http.StatusOK, gin.H{"todos": todos})

}

func main() {
	db = ConnDb()
	r := gin.Default()
	r.POST("/register", Register)
	r.POST("/login", Login)
	authenticated := r.Group("/")
	authenticated.Use(AuthMiddleware())
	{
		authenticated.POST("/create-todo", CreateTodo)
		authenticated.GET("/list-todo", ListTodo)
	}
	r.Run()
}
