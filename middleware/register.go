package middleware

import (
	"github.com/cyberthy/server/structs"
	"github.com/gin-gonic/gin"
)

func RegisterBaseMiddleware(r *gin.Engine, app *structs.App) {
	r.Use(RemoveWWW())

	r.Use(OtherSecurity(app))
	// r.Use(SetCSRFCookie(app))
	// r.Use(VerifyCSRFToken())
	r.Use(CorsMiddleware(app))
	r.Use(CompressMiddleware)
	r.Use(BuildAssetMiddleware(app))
}
