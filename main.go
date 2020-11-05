package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/rs/cors"
	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/fifo"
	"github.com/urfave/negroni"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/strategies/basic"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
	"github.com/shaj13/go-guardian/v2/auth/strategies/union"
)

// Usage:
// curl  -k http://127.0.0.1:8080/v1/book/1449311601 -u admin:admin
// curl -D -  -k http://127.0.0.1:8080/v1/auth/token -u admin:admin <obtain a token>
// curl  -k http://127.0.0.1:8080/v1/book/1449311601 -H "Authorization: Bearer <token>"

var strategy union.Union
var tokenStrategy auth.Strategy
var cacheObj libcache.Cache

func getBookAuthor(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	id := vars["id"]
	books := map[string]string{
		"112333": "Ryan Boyd",
		"434444": "Yvonne Wilson",
		"644444": "Prabath Siriwarden",
	}
	log.Println("looking book", id)

	payload, _ := json.Marshal(books[id])
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(payload))
}

func createToken(w http.ResponseWriter, r *http.Request) {
	log.Println("createToken invoked")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "auth-app",
		"sub": "admin",
		"aud": "any",
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	})
	jwtToken, _ := token.SignedString([]byte("secret"))
	w.Write([]byte(jwtToken))
}

func verifyToken(ctx context.Context, r *http.Request, tokenString string) (auth.Info, time.Time, error) {
	log.Println("verifyToken invoked")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})
	if err != nil {
		return nil, time.Now(), err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		user := auth.NewDefaultUser(claims["sub"].(string), "", nil, nil)
		return user, time.Now(), nil
	}
	return nil, time.Now(), fmt.Errorf("Invaled token")
}

func validateUser(ctx context.Context, r *http.Request, userName, password string) (auth.Info, error) {
	if userName == "admin" && password == "admin" {
		log.Println("userName validated", userName)
		return auth.NewDefaultUser("admin", "1", nil, nil), nil
	}
	return nil, fmt.Errorf("Invalid credentials")
}

func setupGoGuardian() {
	cacheObj = libcache.FIFO.New(0)
	cacheObj.SetTTL(time.Minute * 5)
	cacheObj.RegisterOnExpired(func(key, _ interface{}) {
		cacheObj.Peek(key)
	})

	basicStrategy := basic.NewCached(validateUser, cacheObj)
	tokenStrategy = token.New(verifyToken, cacheObj)
	strategy = union.New(tokenStrategy, basicStrategy)
}

func authHandler(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	log.Println("Executing Auth Middleware")
	_, user, err := strategy.AuthenticateRequest(r)
	if err != nil {
		code := http.StatusUnauthorized
		http.Error(w, http.StatusText(code), code)
		return
	}
	log.Printf("User %s Authenticated\n", user.GetUserName())
	next.ServeHTTP(w,r)
}

func main() {
	log.Println("init")
	setupGoGuardian()
	port := "8080"

	if len(os.Getenv("PORT")) != 0 {
		port = os.Getenv("PORT")
	}

	negroni := negroni.Classic()

	router := mux.NewRouter()
	router.HandleFunc("/v1/auth/token", http.HandlerFunc(createToken)).Methods("GET")
	router.HandleFunc("/v1/book/{id}", http.HandlerFunc(getBookAuthor)).Methods("GET")

	//just for dev * usage
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		// Enable Debugging for testing, consider disabling in production
		Debug: true,
	})

	negroni.Use(c)
	negroni.UseFunc(authHandler)
	negroni.UseHandler(router)

	log.Println("listening http://127.0.0.1:" + port)
	negroni.Run(":" + port)
}
