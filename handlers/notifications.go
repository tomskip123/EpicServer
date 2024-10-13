package handlers

import (
	"fmt"
	"net/http"

	"github.com/cyberthy/server/db"
	"github.com/cyberthy/server/helpers"
	"github.com/cyberthy/server/middleware"
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

var userRequiredFeatures []string

func RegisterNotificationsRoutes(r *gin.Engine, app *structs.App) {
	r.POST("/api/user/notifications/subscribe", HandleUserSubscribe(app))
	r.POST("/api/user/notifications/is-subscribed", HandleIsSubscribed(app))
	r.GET("/api/user/notification/test", HandleTestNotification(app))
}

func HandleIsSubscribed(app *structs.App) gin.HandlerFunc {
	userDb := app.Database.SystemCollections.User
	return middleware.WithAuth(app, userRequiredFeatures, func(ctx *gin.Context, user *structs.UserMemoryCacheItem) {
		// get the endpoint from the payload
		var userSubscription db.UserNotificationSubscriptionModel

		if err := ctx.ShouldBindJSON(&userSubscription); err != nil {
			fmt.Print(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{})
			return
		}

		notificationSubscription, _ := userDb.GetUserNotificationSubscription(ctx, user.UserId, userSubscription)

		ctx.JSON(http.StatusOK, notificationSubscription)
	})
}

func HandleTestNotification(app *structs.App) gin.HandlerFunc {
	userDb := app.Database.SystemCollections.User
	return middleware.WithAuth(app, []string{"admin"}, func(ctx *gin.Context, user *structs.UserMemoryCacheItem) {
		// now we need to securely save this against the user data
		userFromDb, err := userDb.FindOne(user.UserId)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, "")
		}

		if user.Settings.RecieveNotifications {
			for _, notificationSub := range userFromDb.NotificationSubscriptions {

				p := helpers.PushNotificationPayload{
					Title: "Welcome!",
					Body:  "this is the body",
					Type:  "default",
				}

				go helpers.SendNotification(*userFromDb, notificationSub, p)
			}
		}

		ctx.JSON(http.StatusOK, gin.H{"success": true})
	})
}

type UserSubscribeRequest struct {
	DeviceId     string                           `json:"deviceId"`
	UserAgent    string                           `json:"userAgent"`
	Subscription db.NotificationSubscriptionModel `json:"subscription"`
	Timezone     string                           `json:"timezone"`
}

func HandleUserSubscribe(app *structs.App) gin.HandlerFunc {
	userDb := app.Database.SystemCollections.User
	return middleware.WithAuth(app, userRequiredFeatures, func(ctx *gin.Context, user *structs.UserMemoryCacheItem) {
		var userSubscribeRequest UserSubscribeRequest
		if err := ctx.ShouldBindJSON(&userSubscribeRequest); err != nil {
			fmt.Println(userSubscribeRequest)
			ctx.JSON(http.StatusInternalServerError, "")
			return
		}

		fmt.Println("user is" + user.UserId)

		// now we need to securely save this against the user data
		err := userDb.AddNotificationSubscriptions(ctx, user.UserId, db.UserNotificationSubscriptionModel(userSubscribeRequest))
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, userSubscribeRequest)
	})
}
