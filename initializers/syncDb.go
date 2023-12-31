package initializers

import (
	"go-auth/models"
)

func SyncDB() {
	DB.AutoMigrate(&models.User{})
}
