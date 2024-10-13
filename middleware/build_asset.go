package middleware

import (
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

func BuildAssetMiddleware(app *structs.App) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		app.Assets = structs.BuildAssets(app.ServerConfig.ViteManifestFilePath)
		ctx.Next()
	}
}
