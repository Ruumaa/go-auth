package main

import (
	"go-auth/controllers"
	"go-auth/initializers"
	"go-auth/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectDB()
	initializers.SyncDB()
}

func main() {
	router := gin.Default()

	router.POST("/signup", middleware.RequireAuth, controllers.SignUp)
	router.POST("/login", controllers.Login)
	router.GET("/validate", middleware.RequireAuth, controllers.Validate)

	router.Run()
}
